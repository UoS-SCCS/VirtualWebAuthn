/*******************************************************************************
* File:        Web_authn_access_tpm.h
* Description: Functions for Python to install the TPM and call its member
*              functions
*
* Author:      Chris Newton
*
* Created:     Thursday 10 December 2020
*
*
*******************************************************************************/

/*******************************************************************************
*                                                                              *
* (C) Copyright 2020-2021 University of Surrey                                 *
*                                                                              *
* Redistribution and use in source and binary forms, with or without           *
* modification, are permitted provided that the following conditions are met:  *
*                                                                              *
* 1. Redistributions of source code must retain the above copyright notice,    *
* this list of conditions and the following disclaimer.                        *
*                                                                              *
* 2. Redistributions in binary form must reproduce the above copyright notice, *
* this list of conditions and the following disclaimer in the documentation    *
* and/or other materials provided with the distribution.                       *
*                                                                              *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"  *
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE    *
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE   *
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE    *
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR          *
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF         *
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS     *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN      *
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)      *
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE   *
* POSSIBILITY OF SUCH DAMAGE.                                                  *
*                                                                              *
*******************************************************************************/

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
void *install_tpm();

// Setup the TPM
TPM_RC setup_tpm(void *v_tpm_ptr, bool use_hw_tpm, const char *tpm_data_dir, const char *log_filename);

// Set the logging level
TPM_RC set_log_level(void *v_tpm_ptr, int log_level);

// Return the last error
const char *get_last_error(void *v_tpm_ptr);

// Call the TPM class' destructor, flushing any keys from the TPM and freeing any memory
void uninstall_tpm(void *v_tpm_ptr);

// No parent authorisation as we are using the SRK with no password.
Key_data create_and_load_user_key(void *v_tpm_ptr, Byte_array user, Byte_array key_auth);

// No parent authorisation as we are using the SRK with no password, key authorisation not needed to load the key.
TPM_RC load_user_key(void *v_tpm_ptr, Key_data kd, Byte_array user);

Relying_party_key create_and_load_rp_key(void *v_tpm_ptr, Byte_array relying_party, Byte_array user_auth, Byte_array rp_key_auth);

Key_ecc_point load_rp_key(void *v_tpm_ptr, Key_data kd, Byte_array relying_party, Byte_array user_auth);

Ecdsa_sig sign_using_rp_key(void *v_tpm_ptr, Byte_array relying_party, Byte_array signing_data, Byte_array rp_key_auth);

TPM_RC flush_data(void *v_tpm_ptr);

}// end of extern "C"
