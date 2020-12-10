/******************************************************************************
* File:        Create_ecdsa_key.h
* Description: Create an ECDSA signing key
*
* Author:      Chris Newton
*
* Created:     Thursday 7 June 2018
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
*
******************************************************************************/

#pragma once

#include <iostream>
#include <string>
#include "Byte_buffer.h"
#include "Tss_includes.h"

TPM_RC create_ecdsa_key(
TSS_CONTEXT* tssContext,
TPM_HANDLE parent_key_handle,
TPMI_ECC_CURVE curve_ID,
Byte_buffer const& auth,
Create_Out* out	
);

