/***************************************************************************************
* File:        Sha256.cpp
* Description: Code to generate SHA256 using Openssl
*
*
* Author:      Chris Newton
* Created:     Wednesay 21 March 2018
*
* (C) Copyright 2018, University of Surrey.
*
***************************************************************************************/

#include <openssl/sha.h>
#include "Byte_buffer.h"


Byte_buffer sha256_bb(Byte_buffer const &bb)
{
    Byte_buffer hash(SHA256_DIGEST_LENGTH, 0);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &bb[0], bb.size());
    SHA256_Final(&hash[0], &sha256);

    return hash;
}
