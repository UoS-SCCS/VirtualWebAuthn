/*******************************************************************************
* File:        Load_key.cpp
* Description: Load the given key
*
* Author:      Chris Newton
*
* Created:     Monday 14 December 2020
*
*
*******************************************************************************/

/*******************************************************************************
*                                                                              *
* (C) Copyright 2020-2021 University of Surrey                                 *
*                                                                              *
* Redistribution and use in source and binary forms, with or without           *
* modification, are permitted provided that the following conditions are met:  *
*                                                                              *
* 1. Redistributions of source code must retain the above copyright notice,    *
* this list of conditions and the following disclaimer.                        *
*                                                                              *
* 2. Redistributions in binary form must reproduce the above copyright notice, *
* this list of conditions and the following disclaimer in the documentation    *
* and/or other materials provided with the distribution.                       *
*                                                                              *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"  *
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE    *
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE   *
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE    *
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR          *
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF         *
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS     *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN      *
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)      *
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE   *
* POSSIBILITY OF SUCH DAMAGE.                                                  *
*                                                                              *
*******************************************************************************/

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

