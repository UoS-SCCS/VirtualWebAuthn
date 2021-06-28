/*******************************************************************************
* File:        Web_authn_access_tpm.cpp
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

#include <memory>
#include <string>
#include <chrono>
#include <array>
#include <fstream>
#include "Tss_setup.h"
#include "Web_authn_structures.h"
#include "Web_authn_tpm.h"
#include "Web_authn_access_tpm.h"

extern "C" {

void *install_tpm()
{
    void *v_ptr = nullptr;
    auto *tpm_ptr = new Web_authn_tpm();

    v_ptr = reinterpret_cast<void *>(tpm_ptr);

    return v_ptr;
}

#define WEB_AUTHN_ERROR uint32_t(-1)// Define this properly later to not clash with other return values

TPM_RC setup_tpm(void *v_tpm_ptr, bool use_hw_tpm, const char *tpm_data_dir, const char *log_filename)
{
    if (v_tpm_ptr == nullptr) {
        return WEB_AUTHN_ERROR;
    }

    Setup_ptr sp;
    if (use_hw_tpm) {
        sp = std::make_unique<Device_setup>();
    } else {
        sp = std::make_unique<Simulator_setup>();
    }
    sp->data_dir.value = tpm_data_dir;

    auto *tpm_ptr = reinterpret_cast<Web_authn_tpm *>(v_tpm_ptr);

    return tpm_ptr->setup(*sp, log_filename);
}

TPM_RC set_log_level(void *v_tpm_ptr, int log_level)
{
    if (v_tpm_ptr == nullptr) {
        return WEB_AUTHN_ERROR;
    }

    auto *tpm_ptr = reinterpret_cast<Web_authn_tpm *>(v_tpm_ptr);

    return tpm_ptr->set_log_level(log_level);
}

const char *get_last_error(void *v_tpm_ptr)
{
    if (v_tpm_ptr == nullptr) {
        return "NULL pointer passed for the TPM";
    }

    auto *tpm_ptr = reinterpret_cast<Web_authn_tpm *>(v_tpm_ptr);

    static std::string last_error = tpm_ptr->get_last_error();

    return last_error.c_str();
}

Key_data create_and_load_user_key(void *v_tpm_ptr, Byte_array user, Byte_array key_auth)
{
    if (v_tpm_ptr == nullptr) {
        return Key_data{ { 0, nullptr }, { 0, nullptr } };
    }

    auto *tpm_ptr = reinterpret_cast<Web_authn_tpm *>(v_tpm_ptr);

    std::string user_str = byte_array_to_string(user);
    std::string auth_str = byte_array_to_string(key_auth);

    return tpm_ptr->create_and_load_user_key(user_str, auth_str);
}

TPM_RC load_user_key(void *v_tpm_ptr, Key_data kd, Byte_array user)
{
    if (v_tpm_ptr == nullptr) {
        return WEB_AUTHN_ERROR;
    }

    auto *tpm_ptr = reinterpret_cast<Web_authn_tpm *>(v_tpm_ptr);

    std::string user_str = byte_array_to_string(user);

    return tpm_ptr->load_user_key(kd, user_str);
}

Relying_party_key create_and_load_rp_key(void *v_tpm_ptr, Byte_array relying_party, Byte_array user_auth, Byte_array rp_key_auth)
{
    if (v_tpm_ptr == nullptr) {
        return Relying_party_key{ { { 0, nullptr }, { 0, nullptr } }, { { 0, nullptr }, { 0, nullptr } } };
    }

    auto *tpm_ptr = reinterpret_cast<Web_authn_tpm *>(v_tpm_ptr);

    std::string rp_str = byte_array_to_string(relying_party);
    std::string user_auth_str = byte_array_to_string(user_auth);
    std::string rp_key_auth_str = byte_array_to_string(rp_key_auth);

    return tpm_ptr->create_and_load_rp_key(rp_str, user_auth_str, rp_key_auth_str);
}

Key_ecc_point load_rp_key(void *v_tpm_ptr, Key_data kd, Byte_array relying_party, Byte_array user_auth)
{
    if (v_tpm_ptr == nullptr) {
        return Key_ecc_point{ { 0, nullptr }, { 0, nullptr } };
    }

    auto *tpm_ptr = reinterpret_cast<Web_authn_tpm *>(v_tpm_ptr);

    std::string rp_str = byte_array_to_string(relying_party);
    std::string user_auth_str = byte_array_to_string(user_auth);

    return tpm_ptr->load_rp_key(kd, rp_str, user_auth_str);
}

Ecdsa_sig sign_using_rp_key(void *v_tpm_ptr, Byte_array relying_party, Byte_array signing_data, Byte_array rp_key_auth)
{
    if (v_tpm_ptr == nullptr) {
        return Ecdsa_sig{ { 0, nullptr }, { 0, nullptr } };
    }

    auto *tpm_ptr = reinterpret_cast<Web_authn_tpm *>(v_tpm_ptr);

    std::string rp_str = byte_array_to_string(relying_party);
    std::string rp_key_auth_str = byte_array_to_string(rp_key_auth);
    Byte_buffer digest_to_sign = byte_array_to_bb(signing_data);

    return tpm_ptr->sign_using_rp_key(rp_str, digest_to_sign, rp_key_auth_str);
}

TPM_RC flush_data(void *v_tpm_ptr)
{
    if (v_tpm_ptr == nullptr) {
        return WEB_AUTHN_ERROR;
    }

    auto *tpm_ptr = reinterpret_cast<Web_authn_tpm *>(v_tpm_ptr);

    return tpm_ptr->flush_data();
}


void uninstall_tpm(void *v_tpm_ptr)
{
    if (v_tpm_ptr) {
        auto *tpm_ptr = reinterpret_cast<Web_authn_tpm *>(v_tpm_ptr);
        delete tpm_ptr;
    }
    v_tpm_ptr = nullptr;
}


}// End of extern "C"
