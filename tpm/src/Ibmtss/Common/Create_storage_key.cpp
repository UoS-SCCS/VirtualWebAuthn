/******************************************************************************
* File:        create_storage_key.cpp
* Description: Create an ECC storage key
*
* Author:      Chris Newton
*
* Created:     Sunday 13 December 2020
*
* (C) (C) Copyright 2020, University of Surrey, all rights reserved.
*
******************************************************************************/

#include <sstream>
#include <chrono>
#include <cstring>
#include "Tpm_error.h"
#include "Tss_setup.h"
#include "Tpm_defs.h"
#include "Tss_includes.h"
#include "Tss_key_helpers.h"
#include "Create_storage_key.h"

/*
typedef struct {
    TPMI_DH_OBJECT              parentHandle;
    TPM2B_SENSITIVE_CREATE      inSensitive;
    TPM2B_PUBLIC                inPublic;
    TPM2B_DATA                  outsideInfo;
    TPML_PCR_SELECTION          creationPCR;
} Create_In;     
*/

/*
typedef struct {
    TPM2B_PRIVATE       outPrivate;
    TPM2B_PUBLIC        outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST        creationHash;
    TPMT_TK_CREATION    creationTicket;
} Create_Out;
*/

TPM_RC create_storage_key(
TSS_CONTEXT* tss_context,
TPM_HANDLE parent_key_handle,
std::string const& auth,
Create_Out* out
)
{
    TPM_RC rc=0;

	Create_In in;	
	in.parentHandle = parent_key_handle;
	/* Table 133 - Definition of TPMS_SENSITIVE_CREATE Structure <IN>sensitive  */
	/* Table 75 - Definition of Types for TPM2B_AUTH userAuth */
	in.inSensitive.sensitive.userAuth.t.size = auth.size();
	if (auth.size()>0) {
		memcpy(in.inSensitive.sensitive.userAuth.t.buffer,auth.data(),auth.size());
	}

	in.inSensitive.sensitive.data.t.size = 0;
	
	TPMT_PUBLIC& tpmt_public = in.inPublic.publicArea;
	tpmt_public.type = TPM_ALG_ECC;
	tpmt_public.nameAlg = TPM_ALG_SHA256;

	/* Table 32 - TPMA_OBJECT objectAttributes */ // Use NODA, for now
	tpmt_public.objectAttributes.val = obj_storage | TPMA_OBJECT_NODA | TPMA_OBJECT_USERWITHAUTH;

	/* Table 181 - Definition of {ECC} TPMS_ECC_PARMS Structure eccDetail */
	/* Table 129 - Definition of TPMT_SYM_DEF_OBJECT Structure symmetric */
	tpmt_public.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
    tpmt_public.parameters.eccDetail.symmetric.keyBits.aes = 128;
    /* Table 126 - TPMU_SYM_MODE mode */
    tpmt_public.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;

	tpmt_public.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	tpmt_public.parameters.eccDetail.scheme.details.anySig.hashAlg =0;
	tpmt_public.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    tpmt_public.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    tpmt_public.parameters.eccDetail.kdf.details.mgf1.hashAlg = 0;
	
		/* Table 177 - TPMU_PUBLIC_ID unique */
	/* Table 177 - Definition of TPMU_PUBLIC_ID */
	tpmt_public.unique.ecc.x.t.size = 0;
	tpmt_public.unique.ecc.y.t.size = 0;

	tpmt_public.authPolicy.t.size=0;

	in.outsideInfo.t.size = 0;
	/* Table 102 - TPML_PCR_SELECTION creationPCR */
	in.creationPCR.count = 0;

	rc = TSS_Execute(tss_context,
		(RESPONSE_PARAMETERS *)out,
		(COMMAND_PARAMETERS *)&in,
		NULL,
		TPM_CC_Create,
		TPM_RS_PW, NULL, 0,
		TPM_RH_NULL, NULL, 0);
	
    return rc;
}


