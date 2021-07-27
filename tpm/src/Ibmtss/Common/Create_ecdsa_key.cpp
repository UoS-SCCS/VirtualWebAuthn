/*******************************************************************************
* File:        create_ecdsa_key.cpp
* Description: Create an ECDSA signing key
*
* Author:      Chris Newton
*
* Created:     Thursday 7 June 2018
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

#include <sstream>
#include <chrono>
#include <cstring>
#include "Tpm_error.h"
#include "Tss_setup.h"
#include "Tpm_timer.h"
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
std::string const& parent_auth,
TPMI_ECC_CURVE curve_ID,
std::string const& auth,
Create_Out* out
)
{

    TPM_RC rc=0;

	Create_In in;	
	in.parentHandle = parent_key_handle;
	/* Table 133 - Definition of TPMS_SENSITIVE_CREATE Structure <IN>sensitive  */
	/* Table 75 - Definition of Types for TPM2B_AUTH userAuth */
	in.inSensitive.sensitive.userAuth.t.size = static_cast<uint16_t>(auth.size());
	if (auth.size()>0) {
		memcpy(in.inSensitive.sensitive.userAuth.t.buffer,auth.data(),auth.size());
	}
	in.inSensitive.sensitive.data.t.size = 0;
	TPMT_PUBLIC& tpmt_public = in.inPublic.publicArea;
	tpmt_public.type = TPM_ALG_ECC;
	tpmt_public.nameAlg = TPM_ALG_SHA256;

	/* Table 32 - TPMA_OBJECT objectAttributes */
	tpmt_public.objectAttributes.val = TPMA_OBJECT_FIXEDTPM |
		TPMA_OBJECT_NODA |
		TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_SIGN;

	/* Table 181 - Definition of {ECC} TPMS_ECC_PARMS Structure eccDetail */
	/* Table 129 - Definition of TPMT_SYM_DEF_OBJECT Structure symmetric */
	/* Non-storage keys must have TPM_ALG_NULL for the symmetric algorithm */
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

	tpmt_public.authPolicy.t.size=0;

	in.outsideInfo.t.size = 0;
	/* Table 102 - TPML_PCR_SELECTION creationPCR */
	in.creationPCR.count = 0;
	rc = TSS_Execute(tss_context,
		reinterpret_cast<RESPONSE_PARAMETERS *>(out),
		reinterpret_cast<COMMAND_PARAMETERS *>(&in),
		nullptr,
		TPM_CC_Create,
        TPM_RS_PW, parent_auth.c_str(), 0,
		TPM_RH_NULL, NULL, 0);
	
    return rc;
}


