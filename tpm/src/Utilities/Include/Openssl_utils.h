/***************************************************************************
* File:        Openssl_utils.h
* Description: Utility functions for Openssl
*
* Author:      Chris Newton
* Created:     Monday 7 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once 

#include <cstdint>
#include <string>
#include <iostream>
#include <memory>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "Openssl_bnp256.h"
#include "bnp256_param.h"

void init_openssl();

void cleanup_openssl();

void handle_openssl_error();

std::string get_openssl_error();

class Openssl_error : public std::runtime_error
{
public:
    explicit Openssl_error(const char* what) : runtime_error(what) {}
};


