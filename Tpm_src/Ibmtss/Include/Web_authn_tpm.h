/******************************************************************************
* File:        Web_authn_tpm.h
* Description: Implementation of the Web_authn_tpm class for the authenticator
*
* Author:      Chris Newton
*
* Created:     Wednesday 9 December 2020
*
* (C) Copyright 2020, University of Surrey, all rights reserved.
*
******************************************************************************/

#pragma once

#include <string>
#include <chrono>
#include <array>
#include <fstream>
#include "Tss_includes.h"
#include "Tss_setup.h"
#include "Logging.h"
#include "Byte_buffer.h"
#include "Tpm_defs.h"
#include "Web_authn_structures.h"

/**
 * The Web_authn_tpm class, implements the calls needed for the VANET DAA protocol. Details of the protocol are given separately.
 *
 */
class Web_authn_tpm
{
public:
	/**
	 * Default constructor.
	 */
 	Web_authn_tpm() : setup_{false}, hw_tpm_(false), tss_context_(nullptr), last_error_("No error") {}
	Web_authn_tpm(Web_authn_tpm const& t)=delete;
	Web_authn_tpm& operator=(Web_authn_tpm const& t)=delete;
	/**
	 * Setup the Web_authn_tpm class. Installs the persistent SRK, if it is not already in place
	 *
	 * @param tps - the setup data, a Tss_setup object.
	 * @param log_file -the base filename for logging information, the log file will be tps.data_dir.value/log_file<number>
	 *                  the number is generated from the time
	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
    TPM_RC setup(Tss_setup const& tps,std::string log_filename);
	/**
	 * Returns the last error reported, or the empty string. The last error is cleared ready for next time.
	 *
	 * @return - a string containing the last error that was reported.
	 */
	std::string get_last_error();
	/**
	 * The destructor - tidies up. In particular flushing all of the transient keys from the TPM and doing an orderly shutdown.
	 *
	 */
	~Web_authn_tpm();
	/**
	 * Returns the TSS_CONTEXT pointer. Only used for testing, particularly with the TPM simulator.
	 *
	 * @return - a pointer to the current TSS_CONTEXT.
	 */
	TSS_CONTEXT* get_context() {return tss_context_;}


private:
	bool setup_;
    bool hw_tpm_;

	TSS_CONTEXT* tss_context_;
	Log_ptr log_ptr_;
	std::string last_error_;

	Key_data kd_;
	Key_ecc_point pt_;
	Signing_data sd_;	
	Ecdsa_sig sig_;

	void get_tpm_revision_data();
};
