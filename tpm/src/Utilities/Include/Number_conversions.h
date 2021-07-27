/*******************************************************************************
* File:        Number_conversions.h
* Description: Number conversion routines for bin and openssl
*
* Author:      Chris Newton
* Created:     Tuesday 3 April 2018
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

#include <openssl/bn.h>
#include <cstring>
#include <cstdint>
#include "Byte_buffer.h"

using u8_ptr = uint8_t *;
using u8_const_ptr = const uint8_t *;

/*
// The number is made up of words, these define the order of these words
// least significant, or most significant first
const int least_significant_first=-1;
const int most_significant_first=1;
// These define the endianess of the words
const int little_endian_word=-1;
const int big_endian_word=1;
const int native_endianess=0;
// nits of each word to be skipped
const int no_skip=0;
//
*/
// BN_bin2bn(const unsigned char* s,int len, BIGNUM* ret) already defined, but
// included a wrapper here

BIGNUM* bin2bn(u8_const_ptr b, size_t b_size, BIGNUM* bn);

size_t bn2bin(BIGNUM const* bn, u8_ptr& bp);

Byte_buffer bn2bb(BIGNUM const* bn);

