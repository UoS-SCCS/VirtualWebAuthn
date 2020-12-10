/******************************************************************************
* File:        Openssl_bnp256.h
* Description: Openssl code for the bn_p256 EC curve
*
* Author:      Chris Newton
*
* Created:     Friday 18 May 2018
*
*
******************************************************************************/

#pragma once

#include <openssl/ec.h>

EC_GROUP *get_ec_group_bnp256();

