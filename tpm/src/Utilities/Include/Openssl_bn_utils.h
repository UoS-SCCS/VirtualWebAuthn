/*******************************************************************************
* File:        Openssl_bn_utils.h
* Description: Utility functions for Openssl BIGNUMs
*
* Author:      Chris Newton
* Created:     Wednesday 20 June 2018
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
