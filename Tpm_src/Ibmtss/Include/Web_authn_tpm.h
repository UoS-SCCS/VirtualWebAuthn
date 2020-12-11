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
 	Web_authn_tpm() : setup_{false}, hw_tpm_(false), dbg_level_(1), tss_context_(nullptr), last_error_("No error") {}
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

	// Temporary member functions for testing
	Byte_array get_byte_array();
	void put_byte_array(Byte_array ba);
	Two_byte_arrays get_two_byte_arrays();
	void put_two_byte_arrays(Two_byte_arrays tba);

private:
	bool setup_;
    bool hw_tpm_;
	int dbg_level_;

	TSS_CONTEXT* tss_context_;
	Log_ptr log_ptr_;
	std::string last_error_;

	Key_data kd_{{0,nullptr},{0,nullptr}};
	Key_ecc_point pt_{{0,nullptr},{0,nullptr}};
	Byte_array signing_data_{0,nullptr};	
	Ecdsa_sig sig_{{0,nullptr},{0,nullptr}};

	// Temporary, just for testing
	Byte_array ba_{0,nullptr};
	Two_byte_arrays tba_{{0,nullptr},{0,nullptr}};

	/**
	 * Free any memeory that has been allocated, particularly Byte_array's
	 */
	void release_memory();
	/*
	 * Write the given string to the log file
	 * 
	 * @param dbg_level - write to the log if the given value is greater
	 *                    than or equal to dbg_level_
	 * @param str - the string to be written to the log+ newline
	 * 
	 */
	void log(int dbg_level,std::string const& log_str);

};

void tba_copy(Two_byte_arrays&lhs, Two_byte_arrays const& rhs);
