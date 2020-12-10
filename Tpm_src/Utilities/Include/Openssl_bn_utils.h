/***************************************************************************
* File:        Openssl_bn_utils.h
* Description: Utility functions for Openssl BIGNUMs
*
* Author:      Chris Newton
* Created:     Wednesday 20 June 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once 

#include <cstdint>
#include <string>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "Byte_buffer.h"

using Bn_ctx_ptr=std::unique_ptr<BN_CTX,decltype(&::BN_CTX_free)>;
Bn_ctx_ptr new_bn_ctx();

using Bn_ptr=std::unique_ptr<BIGNUM,decltype(&::BN_free)>;
Bn_ptr new_bn();

Byte_buffer bb_mod(Byte_buffer const& num,Byte_buffer const& modulus);

Byte_buffer bb_add(Byte_buffer const& a,Byte_buffer const& b);

Byte_buffer bb_mod_add(Byte_buffer const& a,Byte_buffer const& b,Byte_buffer const& n);

Byte_buffer bb_sub(Byte_buffer const& a,Byte_buffer const& b);

Byte_buffer bb_mod_sub(Byte_buffer const& a,Byte_buffer const& b,Byte_buffer const& n);

Byte_buffer bb_mul(Byte_buffer const& a,Byte_buffer const& b);

Byte_buffer bb_mod_mul(Byte_buffer const& a,Byte_buffer const& b,Byte_buffer const& n);

Byte_buffer bb_signature_calc(Byte_buffer const& a,Byte_buffer const& b,Byte_buffer const& c, Byte_buffer const& modulus);
