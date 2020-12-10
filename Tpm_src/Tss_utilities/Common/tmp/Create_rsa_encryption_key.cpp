/******************************************************************************
* File:        create_rsa_encryption_key.cpp
* Description: Create an RSA encryption key
*
* Author:      Chris Newton
*
* Created:     Monday 21 May 2018
*
*  (C) Copyright 2018, University of Surrey, all rights reserved.
*
******************************************************************************/

#include <iostream>
#include <chrono>
#include <string>
#include <cstring>
#include "Tpm_error.h"
#include "Tpm_defs.h"
#include "Create_rsa_encryption_key.h"

TPM_RC create_rsa_encryption_key(
TSS_CONTEXT* tssContext,
TPM_HANDLE parent_key_handle,
Create_Out* out
)
{
    TPM_RC rc=0;

    Tpm_timer tt;

    Create_In in;
	
    in.parentHandle = parent_key_handle;
    /* Table 75 - Definition of Types for TPM2B_AUTH userAuth */

    in.outsideInfo.t.size = 0;
    in.creationPCR.count = 0;

    TPMT_PUBLIC& tpmtPublic=in.inPublic.publicArea;
    tpmtPublic.type = TPM_ALG_RSA;
    tpmtPublic.nameAlg = TPM_ALG_SHA256;
    
    tpmtPublic.objectAttributes.val = TPMA_OBJECT_FIXEDTPM |
		                      TPMA_OBJECT_FIXEDPARENT |
		                      TPMA_OBJECT_SENSITIVEDATAORIGIN |
		                      TPMA_OBJECT_USERWITHAUTH |
	                              TPMA_OBJECT_NODA |
		                      TPMA_OBJECT_DECRYPT;

    tpmtPublic.parameters.rsaDetail.keyBits = 2048;
    tpmtPublic.parameters.rsaDetail.exponent = 0;

    tpmtPublic.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;



    tpmtPublic.parameters.rsaDetail.scheme.scheme = TPM_ALG_OAEP;
    tpmtPublic.parameters.rsaDetail.scheme.details.oaep.hashAlg=TPM_ALG_SHA256;

    tpmtPublic.unique.rsa.t.size = 0;

    in.inSensitive.sensitive.userAuth.t.size = 0;
    in.inSensitive.sensitive.data.t.size = 0;

    tpmtPublic.authPolicy.t.size =0;


    rc = TSS_Execute(tssContext,
    	    (RESPONSE_PARAMETERS *)out,
	    (COMMAND_PARAMETERS *)&in,
	    NULL,
	    TPM_CC_Create,
	    TPM_RS_PW, NULL, 0,
	    TPM_RH_NULL, NULL, 0);
    if (rc != 0)
    {
	log_ptr->os() << "create_rsa_encryption_key: " << get_tpm_error(rc) << std::endl;
    }

    tpm_timings.add("TPM2_Create",tt.get_duration());

    return rc;
}
