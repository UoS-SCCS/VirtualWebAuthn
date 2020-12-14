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
#include "Tpm_defs.h"
#include "Tpm_param.h"
#include "Tpm_initialisation.h"
#include "Web_authn_structures.h"
#include "Web_authn_access_tpm.h"
#include "Web_authn_tpm.h"

#ifndef IBM_TSS
    #define IBM_TSS
#endif

int main(int argc, char *argv[])
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

	Byte_buffer usr_bb{"alfred"};
	Byte_array usr_ba{0,nullptr};
	bb_to_byte_array(usr_ba,usr_bb);

	Byte_buffer auth_bb{"passwd"};
	Byte_array auth_ba{0,nullptr};
	bb_to_byte_array(auth_ba,auth_bb);
	Key_data kd=create_and_load_user_key(v_tpm_ptr,usr_ba,auth_ba);
	// kd received from web_authn_tpm - no need to free it

	Byte_buffer user_private_data=byte_array_to_bb(kd.private_data);
	Byte_buffer user_public_data=byte_array_to_bb(kd.public_data);
	std::cout << "Public: " << user_public_data << '\n';
	std::cout << "Private: " << user_private_data << '\n';

	release_byte_array(usr_ba);
	release_byte_array(auth_ba);
	uninstall_tpm(v_tpm_ptr);

	v_tpm_ptr=install_tpm();
	if (v_tpm_ptr==nullptr)
	{
		std::cerr << "Unable to install the Web_authn_tpm class\n";
		return EXIT_FAILURE;
	}

	std::string log_file2{"log2"};

	if (setup_tpm(v_tpm_ptr,use_hw_tpm,data_dir.c_str(),log_file2.c_str())!=0) {
		std::cerr << "Error setting up the TPM\n";
		return EXIT_FAILURE;
	}

	bb_to_byte_array(usr_ba,usr_bb);
	bb_to_byte_array(auth_ba,auth_bb);

	Key_data kd_local;
	bb_to_byte_array(kd_local.private_data,user_private_data); 
	bb_to_byte_array(kd_local.public_data,user_public_data); 

	uint32_t rc=load_user_key(v_tpm_ptr,kd_local,usr_ba,auth_ba);
	if (rc==0) {
		std::cout << "User key loaded successfully\n";
	}

	uninstall_tpm(v_tpm_ptr);

	release_byte_array(usr_ba);
	release_byte_array(auth_ba);
	release_byte_array(kd_local.private_data);
	release_byte_array(kd_local.public_data);

    return EXIT_SUCCESS;
}
