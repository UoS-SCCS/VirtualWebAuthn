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
#include "Make_key_persistent.h"
#include "Flush_context.h"
#include "Io_utils.h"
#include "Tpm_error.h"
#include "Create_primary_rsa_key.h"
#include "Create_storage_key.h"
#include "Create_ecdsa_key.h"
#include "Load_key.h"
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

	log(1,"TPM setup complete");

	return rc;
}

Key_data Web_authn_tpm::create_and_load_user_key(std::string const& user, std::string const& authorisation)
{
	log(1,"create_and_load_user_key");
	log(1,vars_to_string("User: ",user,"\tAuthorisation: ",authorisation));

	flush_user_key();
	TPM_RC rc=0;
	try
	{
		Create_Out out;
		rc=create_storage_key(tss_context_,srk_persistent_handle,authorisation,&out);
		if (rc!=0) {
			log(1,"Unable to create the user key");
			throw Tpm_error("Unable to create the user key");
		}
		log(1,"User key created");

		Load_Out load_out;
		rc=load_key(tss_context_,"",srk_persistent_handle,out.outPublic,out.outPrivate,&load_out);
		if (rc!=0) {
			log(1,"Unable to load the user key");
			throw Tpm_error("Unable to load the user key");
		}
	
		user_handle_=load_out.objectHandle;
		if (dbg_level_>0) {
			log_ptr_->os() << "User key loaded, handle: " << std::hex << user_handle_ << '\n';
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
		last_error_="Web_authn_tpm: create_nad_load_user_key: failed - uncaught exception";
	}
	
	return Key_data{{0,nullptr},{0,nullptr}};
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

Web_authn_tpm::~Web_authn_tpm()
{
	if (user_handle_!=0) {
		flush_context(tss_context_,user_handle_);
	}
	if (rp_handle_!=0) {
		flush_context(tss_context_,rp_handle_);
	}
	if (tss_context_)
	{
		shutdown(tss_context_);
		TSS_Delete(tss_context_);
	}
    tss_context_=nullptr;
	release_memory();
}

void ba_copy(Byte_array& lhs, Byte_array const& rhs)
{
	if (&lhs!=&rhs)
	{
		release_byte_array(lhs);		
		lhs.size=rhs.size;
		lhs.data=new Byte[lhs.size];
		if (lhs.data==nullptr)
		{
			std::cerr << "Unable to aloocate memory the a Byte_array\n";
			exit(1);
		}
		memcpy(lhs.data,rhs.data,rhs.size);
	}
}

void tba_copy(Two_byte_arrays&lhs, Two_byte_arrays const& rhs)
{
	ba_copy(lhs.one,rhs.one);
	ba_copy(lhs.two,rhs.two);
}

// Temporary member functions for testing
Byte_array Web_authn_tpm::get_byte_array()
{
	return ba_;	
}

void Web_authn_tpm::put_byte_array(Byte_array ba)
{
	ba_copy(ba_,ba);
}

Two_byte_arrays Web_authn_tpm::get_two_byte_arrays()
{
	return tba_;
}

void Web_authn_tpm::put_two_byte_arrays(Two_byte_arrays tba)
{
	tba_copy(tba_,tba);
}

