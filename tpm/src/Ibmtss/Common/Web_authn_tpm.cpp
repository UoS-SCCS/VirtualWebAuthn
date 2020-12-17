/******************************************************************************
* File:        Web_authn_tpm.cpp
* Description: Implementation of the Web_authn_tpm class for the authenticator
*
* Author:      Chris Newton
*
* Created:     Wednesday 9 December 2020
*
* (C) Copyright 2020, University of Surrey, all rights reserved.
*
******************************************************************************/

#include <chrono>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdlib>
#include "Tss_includes.h"
#include "Tss_setup.h"
#include "Ibmtss_helpers.h"
#include "Make_key_persistent.h"
#include "Flush_context.h"
#include "Io_utils.h"
#include "Tpm_error.h"
#include "Create_primary_rsa_key.h"
#include "Create_storage_key.h"
#include "Create_ecdsa_key.h"
#include "Load_key.h"
#include "Ecdsa_sign.h"
#include "Marshal_data.h"
#include "Openssl_ec_utils.h"
#include "Clock_utils.h"
#include "Tss_setup.h"
#include "Tpm_initialisation.h"
#include "Tpm_defs.h"
#include "Tpm_param.h"
#include "Byte_array.h"
#include "Web_authn_structures.h"
#include "Web_authn_tpm.h"


TPM_RC Web_authn_tpm::setup(Tss_setup const& tps, std::string log_file)
{
	TPM_RC rc=0;
	try
	{
		std::string filename=generate_log_filename(tps.data_dir.value, log_file);
		log_ptr_.reset(new Timed_file_log(filename));
		log_ptr_->set_debug_level(dbg_level_);
		data_dir_=std::string(tps.data_dir.value);
		
		log(1,"TPM setup started");

        hw_tpm_=(tps.t==Tpm_type::device);
        if (!hw_tpm_)
        {
            rc=powerup(tps);
            if (rc!=0)
            {
				log(1,"Web_authn_tpm: setup: Simulator powerup failed");
                throw(Tpm_error("Simulator powerup failed\n"));
            }
        }

        auto nc=set_new_context(tps);
        rc=nc.first;
        if (rc!=0)
        {
			log(1,"Web_authn_tpm: setup: failed to create a TSS context");
            throw(Tpm_error("Web_authn_tpm: setup: failed to create a TSS context\n"));
        }
        tss_context_=nc.second;
		// Fix the data directory to point to a character array inside the class
		// (a fix for now as Tss_setup wasn't designed for this)
		rc=TSS_SetProperty(tss_context_,TPM_DATA_DIR,data_dir_.c_str());

		rc=startup(tss_context_);
		if (rc!=0 && rc!=TPM_RC_INITIALIZE)
		{
			shutdown(tss_context_);
			log(1,"Web_authn_tpm: setup: TPM startup failed (reset the TPM)");
			throw(Tpm_error("TPM startup failed (reset the TPM)"));
		}

        if (!persistent_key_available(tss_context_,srk_persistent_handle)) {
	       	uint32_t object_attributes = TPMA_OBJECT_FIXEDTPM |		// TPMA_OBJECT is a bit field
					    TPMA_OBJECT_FIXEDPARENT |
    		       		TPMA_OBJECT_SENSITIVEDATAORIGIN |
				       	TPMA_OBJECT_USERWITHAUTH |
                       	TPMA_OBJECT_RESTRICTED |
                       	TPMA_OBJECT_NODA |
				       	TPMA_OBJECT_DECRYPT;
			CreatePrimary_Out out;
			rc=create_primary_rsa_key(tss_context_,TPM_RH_OWNER,object_attributes,Byte_buffer(),&out);
			log(1,"Primary key created");
			rc=make_key_persistent(tss_context_,out.objectHandle,srk_persistent_handle);
			log(1,"Primary key made persistent");
		} else {
			log(1,"Primary key already installed");
		}
    }
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=vars_to_string("Web_authn_tpm: setup: Tpm_error: ",e.what());
	}
	catch(std::runtime_error &e)
	{
		rc=2;
		last_error_=vars_to_string("Web_authn_tpm: setup: runtime_error: ", e.what());
	}
	catch (...)
	{
		rc=3;
		last_error_="Web_authn_tpm: setup: failed - uncaught exception";
	}

	log(1,vars_to_string("TPM setup completed with rc=",rc));

	return rc;
}

Key_data Web_authn_tpm::create_and_load_user_key(std::string const& user, std::string const& authorisation)
{
	log(1,"create_and_load_user_key");
	log(1,vars_to_string("User: ",user,"\tAuthorisation: ",authorisation));

	TPM_RC rc=0;
	try
	{
		flush_user_key();
		std::string error;
		Create_Out out;
		rc=create_storage_key(tss_context_,srk_persistent_handle,authorisation,&out);
		if (rc!=0) {
			error=vars_to_string("Unable to create the user key: ",get_tpm_error(rc));
			log(1,error);
			throw Tpm_error(error.c_str());
		}
		log(1,"User key created");

		Load_Out load_out;
		rc=load_key(tss_context_,"",srk_persistent_handle,out.outPublic,out.outPrivate,&load_out);
		if (rc!=0) {
			error=vars_to_string("Unable to load the user key: ",get_tpm_error(rc));
			log(1,error);
			throw Tpm_error(error.c_str());
		}
	
		user_handle_=load_out.objectHandle;
		if (dbg_level_<=1) {
			log_ptr_->os() << "User key loaded, handle: " << std::hex << user_handle_ << std::endl;
		}

		Byte_buffer public_data_bb=marshal_public_data_B(&out.outPublic);
		log(1,vars_to_string("User's public data: ",public_data_bb));
		Byte_buffer private_data_bb=marshal_private_data_B(&out.outPrivate);
		log(1,vars_to_string("User's private data: ",private_data_bb));

		bb_to_byte_array(user_kd_.public_data,public_data_bb);
		bb_to_byte_array(user_kd_.private_data,private_data_bb);

		return user_kd_;

	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=vars_to_string("Web_authn_tpm: create_and_load_user_key: Tpm_error: ",e.what());
	}
	catch(std::runtime_error &e)
	{
		rc=2;
		last_error_=vars_to_string("Web_authn_tpm: create_and_load_user_key: runtime_error: ", e.what());
	}
	catch (...)
	{
		rc=3;
		last_error_="Web_authn_tpm: create_and_load_user_key: failed - uncaught exception";
	}
	
	return Key_data{{0,nullptr},{0,nullptr}};
}

TPM_RC Web_authn_tpm::load_user_key(Key_data const& key, std::string const& user)
{
	log(1,vars_to_string("load_user_key: User: ",user));

	TPM_RC rc=0;

	try
	{
		std::string error;
		flush_user_key();
	
		Byte_buffer public_data_bb=byte_array_to_bb(key.public_data);
		log(1,vars_to_string("User's public data: ",public_data_bb));
		Byte_buffer private_data_bb=byte_array_to_bb(key.private_data);
		log(1,vars_to_string("User's private data: ",private_data_bb));

		TPM2B_PUBLIC tpm2b_public;
		rc=unmarshal_public_data_B(public_data_bb, &tpm2b_public);
		if (rc!=0) {
			error=vars_to_string("Unable to unmarshall the public data for the user key: ",get_tpm_error(rc));
			log(1,error);
			throw Tpm_error(error.c_str());
		}

		TPM2B_PRIVATE tpm2b_private;
		rc=unmarshal_private_data_B(private_data_bb, &tpm2b_private);
		if (rc!=0) {
			error=vars_to_string("Unable to unmarshall the private data for the user key: ",get_tpm_error(rc));
			log(1,error);
			throw Tpm_error(error.c_str());
		}

		Load_Out load_out;
		rc=load_key(tss_context_,"",srk_persistent_handle,tpm2b_public,tpm2b_private,&load_out);
		if (rc!=0) {
			error=vars_to_string("Unable to load the user key: ",get_tpm_error(rc));
			log(1,error);
			throw Tpm_error(error.c_str());
		}

		user_handle_=load_out.objectHandle;

		if (dbg_level_<=1) {
			log_ptr_->os() << "User key loaded, handle: " << std::hex << user_handle_ << std::endl;
		}
		// !!!!!!!!!!!! Should I copy the key data to kd_ for consistency ? !!!!!!!!!!!!
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=vars_to_string("Web_authn_tpm: load_user_key: Tpm_error: ",e.what());
	}
	catch(std::runtime_error &e)
	{
		rc=2;
		last_error_=vars_to_string("Web_authn_tpm: load_user_key: runtime_error: ", e.what());
	}
	catch (...)
	{
		rc=3;
		last_error_="Web_authn_tpm: load_user_key: failed - uncaught exception";
	}

	return rc;
}

Relying_party_key Web_authn_tpm::create_and_load_rp_key(std::string const& relying_party, std::string const& user_auth, std::string const& rp_key_auth)
{
	log(1,"create_and_load_rp_key");
	log(1,vars_to_string("Relying party: ",relying_party,"\tUser (parent) authorisation: ",user_auth, "\tRP auth: ", rp_key_auth));

	TPM_RC rc=0;
	
	try
	{
		std::string error;
		flush_rp_key();
		
		Create_Out out;
		rc=create_ecdsa_key(tss_context_,user_handle_,user_auth,curve_ID,rp_key_auth,&out);
		if (rc!=0) {
			error=vars_to_string("Unable to create the RP key: ",get_tpm_error(rc));
			log(1,error);
			throw Tpm_error(error.c_str());
		}
		log(1,"Relying party key created");

        TPMT_PUBLIC ecdsa_pub_out=out.outPublic.publicArea;
        Byte_buffer ecdsa_key_x=tpm2b_to_bb(ecdsa_pub_out.unique.ecc.x);
        Byte_buffer ecdsa_key_y=tpm2b_to_bb(ecdsa_pub_out.unique.ecc.y);
        log(1,vars_to_string("RP ECDSA public key x: ", ecdsa_key_x));           
        log(1,vars_to_string("RP ECDSA public key y: ", ecdsa_key_y));           

		Load_Out load_out;
		rc=load_key(tss_context_,user_auth,user_handle_,out.outPublic,out.outPrivate,&load_out);
		if (rc!=0) {
			error=vars_to_string("Unable to load the RP key: ",get_tpm_error(rc));
			log(1,error);
			throw Tpm_error(error.c_str());
		}
	
		rp_handle_=load_out.objectHandle;
		if (dbg_level_<=1) {
			log_ptr_->os() << "Relying party key loaded, handle: " << std::hex << rp_handle_ << std::endl;
		}


		Byte_buffer public_data_bb=marshal_public_data_B(&out.outPublic);
		log(1,vars_to_string("RP's public data: ",public_data_bb));
		Byte_buffer private_data_bb=marshal_private_data_B(&out.outPrivate);
		log(1,vars_to_string("RP's private data: ",private_data_bb));

		Relying_party_key rpk;
		bb_to_byte_array(rp_kd_.public_data,public_data_bb);
		bb_to_byte_array(rp_kd_.private_data,private_data_bb);
		rpk.key_blob=rp_kd_;

		bb_to_byte_array(pt_.x_coord,ecdsa_key_x);
		bb_to_byte_array(pt_.y_coord,ecdsa_key_y);
		rpk.key_point=pt_;
		
		return rpk;
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=vars_to_string("Web_authn_tpm: create_and_load_rp_key: Tpm_error: ",e.what());
	}
	catch(std::runtime_error &e)
	{
		rc=2;
		last_error_=vars_to_string("Web_authn_tpm: create_and_load_rp_key: runtime_error: ", e.what());
	}
	catch (...)
	{
		rc=3;
		last_error_="Web_authn_tpm: create_and_load_rp_key: failed - uncaught exception";
	}

	return Relying_party_key{{{0,nullptr},{0,nullptr}},{{0,nullptr},{0,nullptr}}};
}

Key_ecc_point Web_authn_tpm::load_rp_key(Key_data const& key, std::string const& relying_party, std::string const& user_auth)
{
	log(1,vars_to_string("load_rp_key: relying party: ",relying_party," User auth: ",user_auth));

	TPM_RC rc=0;

	try
	{
		std::string error;
		flush_rp_key();

		Byte_buffer public_data_bb=byte_array_to_bb(key.public_data);
		log(1,vars_to_string("RP's public data: ",public_data_bb));
		Byte_buffer private_data_bb=byte_array_to_bb(key.private_data);
		log(1,vars_to_string("RP's private data: ",private_data_bb));

		TPM2B_PUBLIC tpm2b_public;
		rc=unmarshal_public_data_B(public_data_bb, &tpm2b_public);
		if (rc!=0) {
			error=vars_to_string("Unable to unmarshall the public data for the RP key: ",get_tpm_error(rc));
			log(1,error);
			throw Tpm_error(error.c_str());
		}

		TPM2B_PRIVATE tpm2b_private;
		rc=unmarshal_private_data_B(private_data_bb, &tpm2b_private);
		if (rc!=0) {
			error=vars_to_string("Unable to unmarshall the private data for the RP key: ",get_tpm_error(rc));
			log(1,error);
			throw Tpm_error(error.c_str());
		}

		Load_Out load_out;
		rc=load_key(tss_context_,user_auth,user_handle_,tpm2b_public,tpm2b_private,&load_out);
		if (rc!=0) {
			error=vars_to_string("Unable to load the RP key: ",get_tpm_error(rc));
			log(1,error);
			throw Tpm_error(error.c_str());
		}

		rp_handle_=load_out.objectHandle;

		if (dbg_level_<=1) {
			log_ptr_->os() << "RP key loaded, handle: " << std::hex << user_handle_ << std::endl;
		}

        TPMT_PUBLIC ecdsa_pub_out=tpm2b_public.publicArea;
        Byte_buffer ecdsa_key_x=tpm2b_to_bb(ecdsa_pub_out.unique.ecc.x);
        Byte_buffer ecdsa_key_y=tpm2b_to_bb(ecdsa_pub_out.unique.ecc.y);
        log(1,vars_to_string("RP ECDSA public key x: ", ecdsa_key_x));           
        log(1,vars_to_string("RP ECDSA public key y: ", ecdsa_key_y));           

		bb_to_byte_array(pt_.x_coord,ecdsa_key_x);
		bb_to_byte_array(pt_.y_coord,ecdsa_key_y);

		// !!!!!!!!!!!! Should I copy the key data to kd_ for consistency ? !!!!!!!!!!!!
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=vars_to_string("Web_authn_tpm: load_rp_key: Tpm_error: ",e.what());
	}
	catch(std::runtime_error &e)
	{
		rc=2;
		last_error_=vars_to_string("Web_authn_tpm: load_rp_key: runtime_error: ", e.what());
	}
	catch (...)
	{
		rc=3;
		last_error_="Web_authn_tpm: load_user_key: failed - uncaught exception";
	}

	return pt_;
}

Ecdsa_sig Web_authn_tpm::sign_using_rp_key(std::string const& relying_party, Byte_buffer const& digest, std::string const& rp_key_auth)
{
	log(1,vars_to_string("sign_using_rp_key: RP: ",relying_party," RP auth: ",rp_key_auth));
	log(1,vars_to_string("digest to sign: ",digest));

	TPM_RC rc=0;

	try
	{
		std::string error;

		Sign_Out sign_out;

		rc=ecdsa_sign(tss_context_,rp_handle_,digest,rp_key_auth,&sign_out);
		if (rc != 0)
		{
			error=vars_to_string("Sign operation failed: ",get_tpm_error(rc));
			log(1,error);
			throw Tpm_error(error.c_str());
		}

		TPMS_SIGNATURE_ECDSA sig=sign_out.signature.signature.ecdsa;

		Byte_buffer sig_r=tpm2b_to_bb(sig.signatureR);
		Byte_buffer sig_s=tpm2b_to_bb(sig.signatureS);

		log(1,vars_to_string("ECDSA signature R: ",sig_r));
		log(1,vars_to_string("ECDSA signature S: ",sig_s));

		bb_to_byte_array(sig_.sig_r,sig_r);
		bb_to_byte_array(sig_.sig_s,sig_s);

		return sig_;
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=vars_to_string("Web_authn_tpm: sign_using_rp_key: Tpm_error: ",e.what());
	}
	catch(std::runtime_error &e)
	{
		rc=2;
		last_error_=vars_to_string("Web_authn_tpm: sign_using_rp_key: runtime_error: ", e.what());
	}
	catch (...)
	{
		rc=3;
		last_error_="Web_authn_tpm: sign_using_rp_key: failed - uncaught exception";
	}

	return Ecdsa_sig{{0,nullptr},{0,nullptr}};
}

std::string Web_authn_tpm::get_last_error()
{
	// Move the contents of last_error also clears the value
	std::string error(std::move(last_error_));
	last_error_="No error";
	return error;
}

void Web_authn_tpm::flush_user_key()
{
	release_byte_array(user_kd_.public_data);
	release_byte_array(user_kd_.private_data);

	if (user_handle_==0) {
		return;
	}

	flush_rp_key();
	TPM_RC rc=flush_context(tss_context_,user_handle_);
	if (rc!=0) {
		log(0, "Unable to flush the user key");
		throw Tpm_error("Unable to flush the user key");
	}
	user_handle_=0;
	log(1,"User key flushed");
}

void Web_authn_tpm::flush_rp_key()
{
	release_byte_array(rp_kd_.public_data);
	release_byte_array(rp_kd_.private_data);
	release_byte_array(pt_.x_coord);
	release_byte_array(pt_.y_coord);
	if (rp_handle_==0) {
		return;
	}

	TPM_RC rc=flush_context(tss_context_,rp_handle_);
	if (rc!=0) {
		log(0, "Unable to flush the relying party key");
		throw Tpm_error("Unable to flush the relying party key");
	}
	rp_handle_=0;
	log(1,"Relying party key flushed");
}

void Web_authn_tpm::release_memory()
{
	release_byte_array(user_kd_.public_data);
	release_byte_array(user_kd_.private_data);
	release_byte_array(rp_kd_.public_data);
	release_byte_array(rp_kd_.private_data);
	release_byte_array(pt_.x_coord);
	release_byte_array(pt_.y_coord);
	release_byte_array(sig_.sig_r);
	release_byte_array(sig_.sig_s);
	
	// Now the temporary data
	release_byte_array(ba_);
	release_byte_array(tba_.one);
	release_byte_array(tba_.two);
}

void Web_authn_tpm::log(int dbg_level, std::string const& str)
{
	if (dbg_level>dbg_level_) {
		return;
	}
	log_ptr_->os() <<  str << std::endl;
}

TPM_RC Web_authn_tpm::flush_data()
{

	log(1, "flush_data");
	release_memory();

	TPM_RC rc=0;
	try
	{
		flush_user_key();
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=vars_to_string("Flush_data: Tpm_error: ",e.what());
	}
	catch(std::runtime_error &e)
	{
		rc=2;
		last_error_=vars_to_string("Flush_data: runtime_error: ", e.what());
	}
	catch (...)
	{
		rc=3;
		last_error_="Flush_data: failed - uncaught exception";
	}

	return rc;
}

Web_authn_tpm::~Web_authn_tpm()
{
	log(1,"Tidying up ...");

	if (user_handle_!=0) {
		flush_context(tss_context_,user_handle_);
		user_handle_=0;
	}

	if (rp_handle_!=0) {
		flush_context(tss_context_,rp_handle_);
		rp_handle_=0;
	}

	if (tss_context_)
	{
		shutdown(tss_context_);
		TSS_Delete(tss_context_);
	    tss_context_=nullptr;
	}
	release_memory();
}

// Temporary member functions for testing
Byte_array Web_authn_tpm::get_byte_array()
{
	return ba_;	
}

void Web_authn_tpm::put_byte_array(Byte_array ba)
{
	copy_byte_array(ba_,ba);
}

Two_byte_arrays Web_authn_tpm::get_two_byte_arrays()
{
	return tba_;
}

void tba_copy(Two_byte_arrays&lhs, Two_byte_arrays const& rhs)
{
	copy_byte_array(lhs.one,rhs.one);
	copy_byte_array(lhs.two,rhs.two);
}

void Web_authn_tpm::put_two_byte_arrays(Two_byte_arrays tba)
{
	tba_copy(tba_,tba);
}

