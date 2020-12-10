/***************************************************************************
* File:        Number_conversions.cpp
* Description: Number conversion routines
*
* Author:      Chris Newton
* Created:     Tuesday 3 April 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#include <openssl/bn.h>
#include <gmp.h>
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

void bin2bn(u8_const_ptr b, size_t const b_size, BIGNUM *bn)
{
    if (b_size > std::numeric_limits<int>::max()) {
        throw(std::runtime_error("bin2bn: number too large for conversion"));
    }
    BN_bin2bn(b, static_cast<int>(b_size), bn);
}

BIGNUM* bb2bn(Byte_buffer const& n_bb, BIGNUM *bn)
{
    size_t sz=n_bb.size();
    if (sz > std::numeric_limits<int>::max()) {
        throw(std::runtime_error("bb2bn: number too large for conversion"));
    }

    return BN_bin2bn(&n_bb[0],static_cast<int>(sz),bn);    
}


Byte_buffer bn2bb(BIGNUM const *bn)
{
    auto sz = static_cast<size_t>(BN_num_bytes(bn));
    Byte_buffer bb(sz, 0);
    BN_bn2bin(bn, &bb[0]);

    return bb;
}
