/***************************************************************************
* File:        Number_conversions.h
* Description: Number conversion routines for bin and openssl
*
* Author:      Chris Newton
* Created:     Tuesday 3 April 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once

#include <openssl/bn.h>
#include <gmp.h>
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

void bin2bn(u8_const_ptr b, size_t b_size, BIGNUM* bn);

BIGNUM* bb2bn(Byte_buffer const& n_bb, BIGNUM *bn);

size_t bn2bin(BIGNUM const* bn, u8_ptr& bp);

Byte_buffer bn2bb(BIGNUM const* bn);

