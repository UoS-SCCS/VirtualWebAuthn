/*****************************************************************************
* File:        Test_wa_tpm.cpp
* Description: Program to test Web_authn_tpm class
*
* Author:      Chris Newton
*
* Created:     Wednesday 9 December 2020
*
* (C) Copyright 2020, University of Surrey, all rights reserved.
*
*****************************************************************************/

#include <iostream>
#include <random>
#include <chrono>
#include <cstring>
#include "Tss_includes.h"
#include "Ibmtss_helpers.h"
#include "Byte_buffer.h"
#include "Byte_array.h"
#include "Logging.h"
#include "Flush_context.h"
#include "Tpm_error.h"
#include "Tpm_utils.h"
#include "Marshal_data.h"
#include "Tss_setup.h"
#include "Tpm_timer.h"
#include "Tpm_param.h"
#include "Tpm_initialisation.h"
#include "Web_authn_structures.h"
#include "Web_authn_access_tpm.h"
#include "Web_authn_tpm.h"

#ifndef IBM_TSS
    #define IBM_TSS
#endif

int main(/*int argc, char *argv[]*/)
{
	bool use_hw_tpm{false};
	std::string data_dir{"/home/cn0016/TPM_data"};
	std::string log_file{"log"};

	void* v_tpm_ptr=install_tpm();
	if (v_tpm_ptr==nullptr)
	{
		std::cerr << "Unable to install the Web_authn_tpm class\n";
		return EXIT_FAILURE;
	}

	if (setup_tpm(v_tpm_ptr,use_hw_tpm,data_dir.c_str(),log_file.c_str())!=0) {
		std::cerr << "Error setting up the TPM\n";
		return EXIT_FAILURE;
	}

	Byte_buffer bb{"test data for transfer"};
	Byte_array ba{0,nullptr};
	bb_to_byte_array(ba,bb);

	put_byte_array(v_tpm_ptr,ba);

	Byte_array ba2=get_byte_array(v_tpm_ptr); // Freed inside the TPM
	// Copy the data
	Byte_buffer bb2{ba2.data,ba2.size};

	if (bb==bb2) {
		std::cout << "Success with Byte_array transfer\n";
	} else {
		std::cout << "Byte_array transfers failed\n";
	}

	Byte_buffer bb1{"AAAAAAAAAAAAAAAAAAAAAAA Another longer test string ZZZZZZZZZZZZZZZZZZZZZZZZ"};
	Two_byte_arrays tba{{0,nullptr},{0,nullptr}};
	copy_byte_array(tba.one,ba);
	bb_to_byte_array(tba.two,bb1);

	put_two_byte_arrays(v_tpm_ptr,tba);

	Two_byte_arrays tba2=get_two_byte_arrays(v_tpm_ptr);	// Freed inside the TPM
	// Copy the data
	Byte_buffer bb3{tba2.one.data,tba2.one.size};
	Byte_buffer bb4{tba2.two.data,tba2.two.size};
	if (bb==bb3 && bb1==bb4) {
		std::cout << "Success with the Two_byte_array transfers\n";
	} else {
		std::cout << "Two_byte_arrays transfers failed\n";
	}

	release_byte_array(ba);
	release_byte_array(tba.one);
	release_byte_array(tba.two);

	uninstall_tpm(v_tpm_ptr);

	std::cout << "Re-install the wa_tpm class\n";
	v_tpm_ptr=install_tpm();

	std::cout << "Now directly un-install the wa_tpm class\n";
	uninstall_tpm(v_tpm_ptr);

    return EXIT_SUCCESS;
}
