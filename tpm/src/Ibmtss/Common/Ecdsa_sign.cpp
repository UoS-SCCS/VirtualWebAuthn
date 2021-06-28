/*******************************************************************************
* File:        Ecdsa_sign.cpp
* Description: Sign a digest using an ECDSA key (aloready loaded)
*
* Author:      Chris Newton
*
* Created:     Tuesday 15 December 2020
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
#include <cstring>
#include "Byte_buffer.h"
#include "Tss_includes.h"
#include "Ecdsa_sign.h"

TPM_RC ecdsa_sign(
TSS_CONTEXT* tss_context,
TPM_HANDLE handle,
Byte_buffer const& digest_to_sign,
std::string const& ecdsa_auth,
Sign_Out* sign_out
)
{
    TPM_RC rc=0;
    Sign_In sign_in;
    
    sign_in.keyHandle=handle;
    sign_in.inScheme.scheme=TPM_ALG_ECDSA;
    sign_in.inScheme.details.ecdsa.hashAlg=TPM_ALG_SHA256;
    sign_in.digest.t.size = static_cast<uint16_t>(digest_to_sign.size());
    memcpy(&sign_in.digest.t.buffer,digest_to_sign.cdata(),digest_to_sign.size());

    sign_in.validation.tag = TPM_ST_HASHCHECK;
    sign_in.validation.hierarchy = TPM_RH_NULL;
    sign_in.validation.digest.t.size = 0;
        
    if (rc == 0) {
        rc = TSS_Execute(tss_context,
            reinterpret_cast<RESPONSE_PARAMETERS *>(sign_out),
            reinterpret_cast<COMMAND_PARAMETERS *>(&sign_in),
            nullptr,
            TPM_CC_Sign,
            TPM_RS_PW, (ecdsa_auth.size()==0?nullptr:ecdsa_auth.c_str()), 0,            
            TPM_RH_NULL, NULL, 0);
    }
    return rc;
}


