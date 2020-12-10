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
#include "Tpm_error.h"
#include "Create_ecdsa_key.h"
#include "Openssl_ec_utils.h"
#include "Clock_utils.h"
#include "Tss_setup.h"
#include "Tpm_initialisation.h"
#include "Tpm_defs.h"
#include "Tpm_param.h"
#include "Web_authn_tpm.h"


TPM_RC Web_authn_tpm::setup(Tss_setup const& tps)
{
	TPM_RC rc=0;
	try
	{
        hw_tpm_=(tps.t==Tpm_type::device);
        if (!hw_tpm_)
        {
            rc=powerup(tps);
            if (rc!=0)
            {
                throw(Tpm_error("Simulator powerup failed\n"));
            }
        }

        auto nc=set_new_context(tps);
        rc=nc.first;
        if (rc!=0)
        {
            throw(Tpm_error("Web_authn_tpm: setup: failed to create a TSS context\n"));
        }
        tss_context_=nc.second;

		rc=startup(tss_context_);
		if (rc!=0 && rc!=TPM_RC_INITIALIZE)
		{
			shutdown(tss_context_);
			throw(Tpm_error("TPM startup failed (reset the TPM)"));
		}
        
        if (!persistent_key_available(tss_context_,ek_persistent_handle))
        {
			throw(Tpm_error("Web_authn_tpm: setup: setting primary key failed - provision the TPM"));
		}

//        get_tpm_revision_data();
    
        rc=TSS_Delete(tss_context_);
        tss_context_=nullptr;
    }
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Web_authn_tpm: setup: failed - uncaught exception";
	}

	return rc;
}

/*
TPM_RC Web_authn_tpm::get_endorsement_key_data(Byte_buffer& ek_pd)
{
	TPM_RC rc=0;

	try
	{
		if (log_ptr->debug_level()>0)
		{
			log_ptr->write_to_log("Web_authn_tpm: get_endorsement_key_data\n");
		}

		Byte_buffer pd=key_store_.public_data_bb("ek");
		if (pd.size()==0)
		{
			log_ptr->write_to_log("Web_authn_tpm: get_endorsement_key_data: marshalling public data failed\n");
			throw(Tpm_error("Marshalling EK public data failed"));
		}
		ek_pd=pd;
	}
	catch (Tpm_error &e)
	{
		rc=1;
		last_error_=std::string(e.what());
	}
	catch (...)
	{
		rc=2;
		last_error_="Failed - uncaught exception";
	}

	if (log_ptr->debug_level()>0)
	{
		log_ptr->os() << "Web_authn_tpm: get_endorsement_key_data returned:\npd: " << ek_pd.to_hex_string() << std::endl;
	}
	return rc;
}
*/


std::string Web_authn_tpm::get_last_error()
{
	// Move the contents of last_error also clears the value
	std::string error(std::move(last_error_));

	return error;
}

Web_authn_tpm::~Web_authn_tpm()
{
	if (tss_context_)
	{
		// Assumes all keys have bee flushed
		shutdown(tss_context_);
		TSS_Delete(tss_context_);
	}
}

