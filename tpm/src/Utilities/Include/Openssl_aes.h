/***************************************************************************
* File:        Openssl_aes.h
* Description: AES functions 
*
* Author:      Chris Newton
* Created:     Wednesday 30 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once 

#include <cstdint>
#include <iostream>
#include <string>
#include <random>
#include <memory>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "Byte_buffer.h"

const size_t aes_key_bits=128;
const size_t aes_key_bytes=(aes_key_bits+7)/8;
const size_t aes_block_size=AES_BLOCK_SIZE;

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
