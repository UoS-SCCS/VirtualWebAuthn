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
    using Tpm_revision_data=std::array<uint32_t,3>;
	/**
	 * Default constructor.
	 */
 	Web_authn_tpm() : hw_tpm_(false), tss_context_(nullptr) {}
	Web_authn_tpm(Web_authn_tpm const& t)=delete;
	Web_authn_tpm& operator=(Web_authn_tpm const& t)=delete;
	/**
	 * Setup the Web_authn_tpm class. 
	 *
	 * @param tps - the setup data, a Tss_setup object.
	 * @return TPM_RC - this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
    TPM_RC setup(Tss_setup const& tps);
	/**
	 * Returns the TSS_CONTEXT pointer. Only used for testing, particularly with the TPM simulator..
	 *
	 * @return - a pointer to the current TSS_CONTEXT.
	 */


	TSS_CONTEXT* get_context() {return tss_context_;}
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

private:
    bool hw_tpm_;
    Tpm_revision_data revision_data_;
	
	
	TSS_CONTEXT* tss_context_;
	std::string last_error_;

	Key_data kd_;
	Key_ecc_point kp_;
	Signing_data sd_;	
	Ecdsa_sig sig_;

	void get_tpm_revision_data();
};
