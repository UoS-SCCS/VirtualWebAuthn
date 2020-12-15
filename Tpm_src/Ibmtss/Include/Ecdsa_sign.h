/******************************************************************************
* File:        Ecdsa_sign.h
* Description: Sign a digest using an ECDSA key (aloready loaded)
*
* Author:      Chris Newton
*
* Created:     Tuesday 15 December 2020
*
* (C) Copyright 2020, University of Surrey, all rights reserved.
*
******************************************************************************/

#pragma once

#include <iostream>
#include <string>
#include "Byte_buffer.h"
#include "Tss_includes.h"

TPM_RC ecdsa_sign(
TSS_CONTEXT* tss_context,
TPM_HANDLE handle,
Byte_buffer const& digest_to_sign,
std::string const& ecdsa_auth,
Sign_Out* sign_out
);

