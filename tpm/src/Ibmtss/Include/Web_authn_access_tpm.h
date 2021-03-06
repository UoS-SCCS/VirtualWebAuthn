/******************************************************************************
* File:        Web_authn_access_tpm.h
* Description: Functions for Python to install the TPM and call its member
*              functions
*
* Author:      Chris Newton
*
* Created:     Thursday 10 December 2020
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
#include "Web_authn_structures.h"
#include "Web_authn_tpm.h"


extern "C" {
// Allocate memory for the TPM class and return a void* pointer to it
void* install_tpm();

// Setup the TPM
TPM_RC setup_tpm(void* v_tpm_ptr, bool use_hw_tpm, const char* tpm_data_dir, const char* log_filename);

// Return the last error
const char* get_last_error(void* v_tpm_ptr);

// Call the TPM class' destructor, flushing any keys from the TPM and freeing any memory
void uninstall_tpm(void* v_tpm_ptr);

// No parent authorisation as we are using the SRK with no password.
Key_data create_and_load_user_key(void* v_tpm_ptr, Byte_array user, Byte_array key_auth);

// No parent authorisation as we are using the SRK with no password, key authorisation not needed to load the key.
TPM_RC load_user_key(void* v_tpm_ptr, Key_data kd, Byte_array user);

Relying_party_key create_and_load_rp_key(void* v_tpm_ptr, Byte_array relying_party, Byte_array user_auth, Byte_array rp_key_auth);

Key_ecc_point load_rp_key(void* v_tpm_ptr, Key_data kd, Byte_array relying_party, Byte_array user_auth);

Ecdsa_sig sign_using_rp_key(void* v_tpm_ptr, Byte_array relying_party, Byte_array signing_data, Byte_array rp_key_auth);

TPM_RC flush_data(void* v_tpm_ptr);

// Temporary functions for testing
Byte_array get_byte_array(void* v_tpm_ptr);

void put_byte_array(void* v_tpm_ptr, Byte_array ba);

Two_byte_arrays get_two_byte_arrays(void* v_tpm_ptr);

void put_two_byte_arrays(void* v_tpm_ptr, Two_byte_arrays tba);


} // end of extern "C"
