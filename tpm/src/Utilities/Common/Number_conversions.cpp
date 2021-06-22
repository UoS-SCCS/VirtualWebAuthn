/***************************************************************************
* File:        Number_conversions.cpp
* Description: Number conversion routines
*
* Author:      Chris Newton
* Created:     Tuesday 3 April 2018
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
*
****************************************************************************/

#include <openssl/bn.h>
#include <cstring>
#include <limits>
#include "Number_conversions.h"

size_t bn2bin(BIGNUM const *bn, u8_ptr &bp)
{
    if (bp != nullptr) {
        free(bp);       // NOLINT
    }

    auto sz=static_cast<size_t>(BN_num_bytes(bn));
    bp = static_cast<u8_ptr>(malloc(sz));   // NOLINT
    BN_bn2bin(bn, bp);

    return sz;
}

BIGNUM* bin2bn(u8_const_ptr b, size_t const b_size, BIGNUM *bn)
{
    return BN_bin2bn(b, static_cast<int>(b_size), bn);
}

Byte_buffer bn2bb(BIGNUM const *bn)
{
    auto sz = static_cast<size_t>(BN_num_bytes(bn));
    Byte_buffer bb(sz, 0);
    BN_bn2bin(bn, &bb[0]);

    return bb;
}
