/******************************************************************************
* File:        create_primary_rsa_key.h
* Description: Create primary RSA key in the endorsement hierarchy
*
* Author:      Chris Newton
*
* Created:     Thursday 5 April 2018
* Upadted:     Thursday 10 December 2020
*
* Closely modelled on example code from the IBM TSS software
*
* (C) Copyright 2018-2020, University of Surrey, all rights reserved.
*
******************************************************************************/

#pragma once

#include <iostream>
#include <cstring>
#include "Byte_buffer.h"
#include "Tss_includes.h"
#include "Openssl_aes.h"

// Create a primary key in the endorsement hierarchy
TPM_RC create_primary_rsa_key(
TSS_CONTEXT *tssContext,
TPMI_RH_HIERARCHY primary_handle,
uint32_t attributes,
Byte_buffer policy,
CreatePrimary_Out* out
);
