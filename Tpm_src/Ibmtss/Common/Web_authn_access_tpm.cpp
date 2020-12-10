/******************************************************************************
* File:        Web_authn_access_tpm.cpp
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

#include <string>
#include <chrono>
#include <array>
#include <fstream>
#include "Web_authn_structures.h"
#include "Web_authn_tpm.h"
#include "Web_authn_access_tpm.h"


void* install_tpm()
{
	void* v_ptr=nullptr;
	Web_authn_tpm* tpm_ptr=new Web_authn_tpm();

	v_ptr=reinterpret_cast<void*>(tpm_ptr);

	return v_ptr;
}

int setup_tpm(void* v_tpm_ptr, bool use_hw_tpm, const char* log_filename)
{
	return 0;
}

const char* get_last_error(void* tpm_ptr)
{
	return "Not yet implemented";
}

void uninstall_tpm(void* v_tpm_ptr)
{
	if (v_tpm_ptr)
	{
		Web_authn_tpm* tpm_ptr=reinterpret_cast<Web_authn_tpm*>(v_tpm_ptr);
		delete tpm_ptr;
	}
}