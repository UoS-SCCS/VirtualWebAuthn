/******************************************************************************
* File:        Load_key.cpp
* Description: Load the given key
*
* Author:      Chris Newton
*
* Created:     Monday 14 December 2020
*
* (C) Copyright 2020, University of Surrey, all rights reserved.
*
******************************************************************************/

#include <iostream>
#include <string>
#include "Byte_buffer.h"
#include "Tss_includes.h"
#include "Load_key.h"

TPM_RC load_key(
TSS_CONTEXT* tss_context,
std::string parent_auth,
TPM_HANDLE parent_handle,
TPM2B_PUBLIC tpm_public,
TPM2B_PRIVATE tpm_private,
Load_Out* out
)
{
    Load_In load_key_in;
 
    load_key_in.parentHandle=parent_handle;
    load_key_in.inPrivate=tpm_private;
    load_key_in.inPublic=tpm_public;
    TPM_RC rc = TSS_Execute(tss_context,
        reinterpret_cast<RESPONSE_PARAMETERS *>(out),
        reinterpret_cast<COMMAND_PARAMETERS *>(&load_key_in),
        nullptr,
        TPM_CC_Load,
        TPM_RS_PW, (parent_auth.size()==0?nullptr:parent_auth.c_str()), 0,
        TPM_RH_NULL, NULL, 0);
    return rc;
}

