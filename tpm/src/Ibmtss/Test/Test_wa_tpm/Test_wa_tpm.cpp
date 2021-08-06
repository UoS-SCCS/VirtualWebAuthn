/*******************************************************************************
* File:        Test_wa_tpm.cpp
* Description: Program to test Web_authn_tpm class
*
* Author:      Chris Newton
*
* Created:     Wednesday 9 December 2020
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

#include <iostream>
#include <random>
#include <chrono>
#include <cstring>
#include "Tss_includes.h"
#include "Ibmtss_helpers.h"
#include "Byte_buffer.h"
#include "Byte_array.h"
#include "Logging.h"
#include "Io_utils.h"
#include "Flush_context.h"
#include "Tpm_error.h"
#include "Tpm_utils.h"
#include "Marshal_data.h"
#include "Tss_setup.h"
#include "Tpm_timer.h"
#include "Tpm_param.h"
#include "Sha.h"
#include "Tpm_initialisation.h"
#include "Web_authn_structures.h"
#include "Web_authn_access_tpm.h"
#include "Web_authn_tpm.h"

#ifndef IBM_TSS
#define IBM_TSS
#endif

int main(int argc, char *argv[])
{
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <data directory> <log level (1, 2 or 3)>\n";
        return EXIT_FAILURE;
    }

    std::string data_dir{ argv[1] };
    int log_level = std::atoi(argv[2]);
    if (log_level < 1 || log_level > 3) {
        std::cerr << "Invalid value for the log level: " << log_level << ".\n";
        std::cerr << "Usage: " << argv[0] << " <data directory> <log level (1, 2 or 3>\n";
        return EXIT_FAILURE;
    }

    bool tests_ok{ true };
    bool use_hw_tpm{ false };
    std::string log_file_prefix{ "log" };

    // curve_name corresponds to TPMI_ECC_CURVE curve_ID=TPM_ECC_NIST_P256;
    std::string curve_name = "prime256v1";

    void *v_tpm_ptr = install_tpm();
    if (v_tpm_ptr == nullptr) {
        std::cerr << "Unable to install the Web_authn_tpm class\n";
        return EXIT_FAILURE;
    }
    // Now set the debug level, so we see what's happening
    if (set_log_level(v_tpm_ptr, log_level) != 0) {
        std::cerr << get_last_error(v_tpm_ptr) << '\n';
        return EXIT_FAILURE;
    }

    if (setup_tpm(v_tpm_ptr, use_hw_tpm, data_dir.c_str(), log_file_prefix.c_str()) != 0) {
        std::cerr << "Error setting up the TPM\n";
        return EXIT_FAILURE;
    }


    Byte_buffer usr_bb{ "alfred" };
    Byte_array usr_ba{ 0, nullptr };
    bb_to_byte_array(usr_ba, usr_bb);

    Byte_buffer usr_auth_bb{ "passwd" };
    Byte_array usr_auth_ba{ 0, nullptr };
    bb_to_byte_array(usr_auth_ba, usr_auth_bb);

    Key_data kd_local{ { 0, nullptr }, { 0, nullptr } };

    Byte_buffer rp_bb{ "Troy" };
    Byte_array rp_ba;
    bb_to_byte_array(rp_ba, rp_bb);
    Byte_buffer rp_key_auth_bb{ "rpPwd" };
    Byte_array rp_key_auth_ba;
    bb_to_byte_array(rp_key_auth_ba, rp_key_auth_bb);

    Key_data rp_kd{ { 0, nullptr }, { 0, nullptr } };

    Byte_buffer msg{ "This is a test message ZZZ" };
    Byte_buffer digest = sha256_bb(msg);
    Byte_array digest_ba{ 0, nullptr };
    bb_to_byte_array(digest_ba, digest);

    try {
        Key_data kd = create_and_load_user_key(v_tpm_ptr, usr_ba, usr_auth_ba);
        // kd received from web_authn_tpm - no need to free it
        if (kd.private_data.size == 0) {
            std::string error = vars_to_string("create_and_load_user_key failed: ", get_last_error(v_tpm_ptr));
            throw std::runtime_error(error);
        }

        Byte_buffer user_private_data = byte_array_to_bb(kd.private_data);
        Byte_buffer user_public_data = byte_array_to_bb(kd.public_data);
        std::cout << "Public: " << user_public_data << '\n';
        std::cout << "Private: " << user_private_data << '\n';

        TSS_RC rc = flush_data(v_tpm_ptr);
        if (rc != 0) {
            std::string error = vars_to_string("flush_data failed: ", get_last_error(v_tpm_ptr));
            throw std::runtime_error(error);
        }

        bb_to_byte_array(kd_local.private_data, user_private_data);
        bb_to_byte_array(kd_local.public_data, user_public_data);

        rc = load_user_key(v_tpm_ptr, kd_local, usr_auth_ba);
        if (rc != 0) {
            std::string error = vars_to_string("User key failed to load: ", get_last_error(v_tpm_ptr));
            throw std::runtime_error(error);
        }

        Relying_party_key rpk = create_and_load_rp_key(v_tpm_ptr, rp_ba, usr_auth_ba, rp_key_auth_ba);
        // rpk received from web_authn_tpm - no need to free it
        if (rpk.key_blob.private_data.size == 0) {
            std::string error = vars_to_string("create_and_load_rp_key failed: ", get_last_error(v_tpm_ptr));
            throw std::runtime_error(error);
        }

        Byte_buffer rp_private_data = byte_array_to_bb(rpk.key_blob.private_data);
        Byte_buffer rp_public_data = byte_array_to_bb(rpk.key_blob.public_data);
        std::cout << "Public: " << rp_public_data << '\n';
        std::cout << "Private: " << rp_private_data << '\n';

        Key_ecc_point const &pt = rpk.key_point;
        Byte_buffer ecdsa_key_x = byte_array_to_bb(pt.x_coord);
        Byte_buffer ecdsa_key_y = byte_array_to_bb(pt.y_coord);

        std::cout << "ECDSA public key x: " << ecdsa_key_x << '\n';
        std::cout << "ECDSA public key y: " << ecdsa_key_y << '\n';

        copy_byte_array(rp_kd.private_data, rpk.key_blob.private_data);
        copy_byte_array(rp_kd.public_data, rpk.key_blob.public_data);

        Key_ecc_point loaded_rp_key = load_rp_key(v_tpm_ptr, rp_kd, rp_ba, usr_auth_ba);
        // loaded_rp_key received from web_authn_tpm - no need to free it
        if (loaded_rp_key.x_coord.size == 0) {
            std::string error = vars_to_string("Failed to load the RP key failed: ", get_last_error(v_tpm_ptr));
            throw std::runtime_error(error);
        }

        ecdsa_key_x = byte_array_to_bb(loaded_rp_key.x_coord);
        ecdsa_key_y = byte_array_to_bb(loaded_rp_key.y_coord);
        std::cout << "ECDSA public key x: " << ecdsa_key_x << '\n';
        std::cout << "ECDSA public key y: " << ecdsa_key_y << '\n';
        G1_point ecdsa_public_key;
        ecdsa_public_key = std::make_pair(ecdsa_key_x, ecdsa_key_y);

        Ecdsa_sig sig = sign_using_rp_key(v_tpm_ptr, rp_ba, digest_ba, rp_key_auth_ba);
        // sig received from web_authn_tpm - no need to free it
        if (sig.sig_r.size == 0) {
            std::string error = vars_to_string("Signature using the RP key failed: ", get_last_error(v_tpm_ptr));
            throw std::runtime_error(error);
        }

        Byte_buffer sig_r = byte_array_to_bb(sig.sig_r);
        Byte_buffer sig_s = byte_array_to_bb(sig.sig_s);
        std::cout << "ECDSA signature R: " << sig_r << '\n';
        std::cout << "ECDSA signature S: " << sig_s << '\n';

        if (verify_ecdsa_signature(curve_name, ecdsa_public_key, digest, sig_r, sig_s)) {
            std::cout << "OpenSSL verified the ECDSA Signature\n";
        } else {
            std::cout << "OpenSSL failed to verify the ECDSA Signature\n";
        }
    } catch (std::exception const &e) {
        std::cerr << e.what() << std::endl;
        tests_ok = false;
    }

    TSS_RC rc = flush_data(v_tpm_ptr);
    if (rc != 0) {
        std::cerr << "flush_data failed: " << get_last_error(v_tpm_ptr) << std::endl;
    }
    uninstall_tpm(v_tpm_ptr);

    release_byte_array(usr_ba);
    release_byte_array(usr_auth_ba);
    release_byte_array(kd_local.private_data);
    release_byte_array(kd_local.public_data);
    release_byte_array(rp_ba);
    release_byte_array(rp_key_auth_ba);
    release_byte_array(rp_kd.private_data);
    release_byte_array(rp_kd.public_data);
    release_byte_array(digest_ba);

    return tests_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
