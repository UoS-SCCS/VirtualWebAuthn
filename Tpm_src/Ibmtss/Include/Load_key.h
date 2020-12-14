/******************************************************************************
* File:        Load_key.h
* Description: Load the given key
*
* Author:      Chris Newton
*
* Created:     Monday 14 December 2020
*
* (C) Copyright 2020, University of Surrey, all rights reserved.
*
******************************************************************************/

#pragma once

#include <iostream>
#include <string>
#include "Byte_buffer.h"
#include "Tss_includes.h"

TPM_RC load_key(
TSS_CONTEXT* tssContext,
std::string parent_auth,
TPM_HANDLE parent_handle,
TPM2B_PUBLIC tpm_public,
TPM2B_PRIVATE tpm_private,
Load_Out* out
);
