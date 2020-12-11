/******************************************************************************
* File:        Web_authn_access_tpm.h
* Description: Functions for Python to install the TPM and call its member functions
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
#include "Web_authn_structures.h"
#include "Web_authn_tpm.h"


extern "C" {

void* install_tpm();

int setup_tpm(void* v_tpm_ptr, bool use_hw_tpm, const char* tpm_data_dir, const char* log_filename);

const char* get_last_error(void* v_tpm_ptr);

void uninstall_tpm(void* v_tpm_ptr);


Byte_array get_byte_array(void* v_tpm_ptr);

void put_byte_array(void* v_tpm_ptr, Byte_array ba);

Two_byte_arrays get_two_byte_arrays(void* v_tpm_ptr);

void put_two_byte_arrays(void* v_tpm_ptr, Two_byte_arrays tba);


} // end of extern "C"