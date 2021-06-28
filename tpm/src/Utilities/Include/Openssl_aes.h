/*******************************************************************************
* File:        Openssl_aes.h
* Description: AES functions 
*
* Author:      Chris Newton
* Created:     Wednesday 30 May 2018
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

#include <cstdint>
#include <iostream>
#include <string>
#include <random>
#include <memory>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "Byte_buffer.h"

constexpr size_t aes_key_bits=128;
constexpr size_t aes_key_bytes=(aes_key_bits+7)/8;
constexpr size_t aes_block_size=AES_BLOCK_SIZE;

/*
>>>>>>> using_cmake
using Evp_cipher_ctx_ptr=std::unique_ptr<EVP_CIPHER_CTX,decltype(&::EVP_CIPHER_CTX_free)>;
static Evp_cipher_ctx_ptr new_evp_cipher_ctx(){return Evp_cipher_ctx_ptr(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);}

Byte_buffer initialise_random_iv(size_t size);

AES_KEY get_aes_key(Byte_buffer const& aes_bb);

Byte_buffer encrypt_aes128(
Byte_buffer const& pt,
Byte_buffer const& aes_key_bb
);

Byte_buffer ossl_encrypt(
std::string const& cipher_name,
Byte_buffer const& id,
Byte_buffer const& aes_key_bb,
Byte_buffer const& initial_iv
);

Byte_buffer ossl_decrypt(
std::string const& cipher_name,
Byte_buffer const& id,
Byte_buffer const& aes_key_bb,
Byte_buffer const& initial_iv
);
*/
