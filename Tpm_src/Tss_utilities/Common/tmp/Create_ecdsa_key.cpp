/******************************************************************************
* File:        create_ecdsa_key.cpp
* Description: Create an ECDSA signing key
*
* Author:      Chris Newton
*
* Created:     Thursday 7 June 2018
*
* (C) (C) Copyright 2018, University of Surrey, all rights reserved.
*
******************************************************************************/

#include <sstream>
#include <chrono>
#include <string>
#include "Tpm_error.h"
#include "Tss_setup.h"
#include "Tpm_defs.h"
#include "Create_ecdsa_key.h"

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

TPM_RC create_ecdsa_key(
TSS_CONTEXT* tss_context,
TPM_HANDLE parent_key_handle,
TPMI_ECC_CURVE curve_ID,
Create_Out* out
)
{
	Tpm_type tpm_if=tpm_type(tss_context);
	if (tpm_if==Tpm_type::device && curve_ID==TPM_ECC_BN_P256)
	{
		log_ptr->write_to_log("create_ecdsa_key: cannot use BN_P256 with the dev interface\n");
		throw(Tpm_error("create_ecdsa_key: cannot use BN_P256 with the dev interface"));
	}

    TPM_RC rc=0;

	Tpm_timer tt;

	Create_In in;	
	in.parentHandle = parent_key_handle;
	/* Table 133 - Definition of TPMS_SENSITIVE_CREATE Structure <IN>sensitive  */
	/* Table 75 - Definition of Types for TPM2B_AUTH userAuth */
	in.inSensitive.sensitive.userAuth.t.size = 0;
	in.inSensitive.sensitive.data.t.size = 0;

	in.outsideInfo.t.size = 0;
	in.creationPCR.count = 0;

	TPMT_PUBLIC& tpmt_public = in.inPublic.publicArea;
	tpmt_public.type = TPM_ALG_ECC;
	tpmt_public.nameAlg = TPM_ALG_SHA256;
	tpmt_public.objectAttributes.val = TPMA_OBJECT_FIXEDTPM |
		TPMA_OBJECT_NODA |
		TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_SIGN;

        // No policy used
	tpmt_public.authPolicy.t.size=0;

	// Non-storage keys must have TPM_ALG_NULL for the symmetric algorithm 
	tpmt_public.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;

	tpmt_public.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
	tpmt_public.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;

	tpmt_public.parameters.eccDetail.curveID = curve_ID;
	// Although the curve requires a particular KDF algorithm this seems to be ignored 
	// here unlike the signing scheme!
	tpmt_public.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

	/* Table 177 - TPMU_PUBLIC_ID unique */
	/* Table 177 - Definition of TPMU_PUBLIC_ID */
	tpmt_public.unique.ecc.x.t.size = 0;
	tpmt_public.unique.ecc.y.t.size = 0;

	rc = TSS_Execute(tss_context,
		(RESPONSE_PARAMETERS *)out,
		(COMMAND_PARAMETERS *)&in,
		NULL,
		TPM_CC_Create,
		TPM_RS_PW, NULL, 0,
		TPM_RH_NULL, NULL, 0);
	if (rc != 0)
	{
		log_ptr->os() << "create_ecdsa_key: " << get_tpm_error(rc) << std::endl;
        throw(Tpm_error("create ecdsa key failed"));
	}

	tpm_timings.add("TPM2_Create",tt.get_duration());
	
    return rc;
}


