/******************************************************************************
* File:        create_hmac_key.cpp
* Description: Create an HMAC key
*
* Author:      Chris Newton
*
* Created:     Sunday 22 March 2020
*
* (C) (C) Copyright 2020, University of Surrey, all rights reserved.
*
******************************************************************************/

#include <sstream>
#include <chrono>
#include <string>
#include "Tpm_error.h"
#include "Tss_setup.h"
#include "Tpm_defs.h"
#include "Create_hmac_key.h"

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

TPM_RC create_hmac_key(
TSS_CONTEXT* tss_context,
TPM_HANDLE parent_key_handle,
Create_Out* out
)
{
    TPM_RC rc=0;

	Tpm_timer tt;

	Create_In in;	
	in.parentHandle = parent_key_handle;
	/* Table 133 - Definition of TPMS_SENSITIVE_CREATE Structure <IN>sensitive  */
	/* Table 75 - Definition of Types for TPM2B_AUTH userAuth */
	in.inSensitive.sensitive.userAuth.t.size = 0;
	in.inSensitive.sensitive.data.t.size = 0;
	TPMT_PUBLIC& tpmt_public = in.inPublic.publicArea;
	tpmt_public.type = TPM_ALG_KEYEDHASH;
	tpmt_public.nameAlg = TPM_ALG_SHA256;

	/* Table 32 - TPMA_OBJECT objectAttributes */
	tpmt_public.objectAttributes.val = TPMA_OBJECT_FIXEDTPM |
		TPMA_OBJECT_NODA |
		TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_SIGN;

	tpmt_public.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
	tpmt_public.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA256;
	
	/* Table 177 - TPMU_PUBLIC_ID unique */
	/* Table 177 - Definition of TPMU_PUBLIC_ID */
	tpmt_public.unique.sym.t.size = 0;

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
	if (rc != 0)
	{
		log_ptr->os() << "create_hmac_key: " << get_tpm_error(rc) << std::endl;
        throw(Tpm_error("create hmac key failed"));
	}

	tpm_timings.add("TPM2_Create",tt.get_duration());
	
    return rc;
}


