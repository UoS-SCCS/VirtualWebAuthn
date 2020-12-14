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
	 * Creates a new user (storage) key and loads it ready for use. If a user key is already in place, it and its relying
	 * party key (if one is loaded) are flushed and their data removed.
	 * 
	 * @param user - an identifier for the key user (at the moment this is not used).
	 * @param authorisation - authorisation string for the key (password). This could be empty.
	 *                  
	 * @return Key_data - the public and private parts of the key, null Byte_arrays if the call fails.
	 */
	Key_data create_and_load_user_key(std::string const& user, std::string const& authorisation);
	/**
	 * Loads a user (storage) key and loads it ready for use. If a user key is already in place, it and its relying
	 * party key (if one is loaded) are flushed and their data removed.
	 * 
	 * @param key - the public and private parts of the key
	 * @param user - an identifier for the key user (at the moment this is not used).
	 * @param authorisation - authorisation string for the  key (password). This could be empty.
	 *                   
	 * @return TPM_RC- this will be zero for a successful call. If non-zero use get_last_error() to return the error.
	 */
	TPM_RC load_user_key(Key_data const& key, std::string const& user, std::string const& authorisation);
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

	TPM_HANDLE user_handle_{0};
	TPM_HANDLE rp_handle_{0};


	// Data for transfer to the caller
	Key_data user_kd_{{0,nullptr},{0,nullptr}};
	Key_data rp_kd_{{0,nullptr},{0,nullptr}};
	Key_ecc_point pt_{{0,nullptr},{0,nullptr}};
	Ecdsa_sig sig_{{0,nullptr},{0,nullptr}};

	// Temporary, just for testing
	Byte_array ba_{0,nullptr};
	Two_byte_arrays tba_{{0,nullptr},{0,nullptr}};


	/**
	 * Flush the user key and, if necessary any associated relying party key
	 * also  frees any associated data (in Byte_arrays).
	 */
	void flush_user_key();
	/**
	 * Flush the relying party key, only one loaded at a time, also  frees 
	 * any associated data (in Byte_arrays).
	 */
	void flush_rp_key();
	/**
	 * Free any memeory that has been allocated, particularly Byte_array's
	 */
	void release_memory();
	/*
	 * Write the given string to the log file
	 * 
	 * @param dbg_level - write to the log if the given value is less
	 *                    than or equal to dbg_level_
	 * @param str - the string to be written to the log+ newline
	 * 
	 */
	void log(int dbg_level,std::string const& log_str);

};

void tba_copy(Two_byte_arrays&lhs, Two_byte_arrays const& rhs);
