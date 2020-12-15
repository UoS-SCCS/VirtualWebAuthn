/******************************************************************************
* File:        Ecdsa_sign.cpp
* Description: Sign a digest using an ECDSA key (aloready loaded)
*
* Author:      Chris Newton
*
* Created:     Tuesday 15 December 2020
*
* (C) Copyright 2020, University of Surrey, all rights reserved.
*
******************************************************************************/

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
    sign_in.digest.t.size = digest_to_sign.size();
    memcpy(&sign_in.digest.t.buffer,digest_to_sign.cdata(),digest_to_sign.size());

    sign_in.validation.tag = TPM_ST_HASHCHECK;
    sign_in.validation.hierarchy = TPM_RH_NULL;
    sign_in.validation.digest.t.size = 0;
        
    if (rc == 0) {
        rc = TSS_Execute(tss_context,
            (RESPONSE_PARAMETERS *)sign_out,
            (COMMAND_PARAMETERS *)&sign_in,
            NULL,
            TPM_CC_Sign,
            TPM_RS_PW, (ecdsa_auth.size()==0?nullptr:ecdsa_auth.c_str()), 0,            
            TPM_RH_NULL, NULL, 0);
    }
    return rc;
}


