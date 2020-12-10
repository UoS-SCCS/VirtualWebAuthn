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
#include "Tss_setup.h"
#include "Web_authn_structures.h"
#include "Web_authn_tpm.h"
#include "Web_authn_access_tpm.h"

extern "C" {

void* install_tpm()
{
	void* v_ptr=nullptr;
	Web_authn_tpm* tpm_ptr=new Web_authn_tpm();

	v_ptr=reinterpret_cast<void*>(tpm_ptr);

	return v_ptr;
}

int setup_tpm(void* v_tpm_ptr, bool use_hw_tpm, const char* tpm_data_dir, const char* log_filename)
{
	if (v_tpm_ptr==nullptr) {
		return -1;
	}

	Setup_ptr sp;
	if (use_hw_tpm) {
		sp.reset(new Device_setup());
	}
	else {
		sp.reset(new Simulator_setup());
	}
	sp->data_dir.value=tpm_data_dir;

	Web_authn_tpm* tpm_ptr=reinterpret_cast<Web_authn_tpm*>(v_tpm_ptr);

	return tpm_ptr->setup(*sp,log_filename);
}

const char* get_last_error(void* v_tpm_ptr)
{
	if (v_tpm_ptr==nullptr) {
		return "NULL pointer passed for the TPM";
	}

	Web_authn_tpm* tpm_ptr=reinterpret_cast<Web_authn_tpm*>(v_tpm_ptr);

	static std::string last_error=tpm_ptr->get_last_error();

	return last_error.c_str();

}

void uninstall_tpm(void* v_tpm_ptr)
{
	if (v_tpm_ptr)
	{
		Web_authn_tpm* tpm_ptr=reinterpret_cast<Web_authn_tpm*>(v_tpm_ptr);
		delete tpm_ptr;
	}
}

} // End of extern "C"
