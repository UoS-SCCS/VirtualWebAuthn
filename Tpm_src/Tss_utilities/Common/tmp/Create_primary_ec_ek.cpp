/*****************************************************************************
* File:        Create_primary_ec_ek.cpp
* Description: Create a primary EC key in the endorsement hierarchy
*
* Author:      Chris Newton
*
* Created:     Thursday 5 April 2018
*
* Closely modelled on example code from the IBM TSS software
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
*
******************************************************************************/

#include <chrono>
#include <iostream>
#include <cstring>
#include "Create_primary_ec_ek.h"
#include "Tpm_error.h"

// TCG Infrastructure Work Group (IWG) default EK primary key policy

static const unsigned char iwgPolicy[] = {
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
    0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
    0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
};

// Create a primary key in the endorsement hierarchy
TPM_RC create_primary_ec_ek(
TSS_CONTEXT* tss_context,
CreatePrimary_Out* out,
std::ostream& os	
)
{
    TPM_RC rc = 0;
    CreatePrimary_In in;
 
/*
typedef struct {
    TPMI_RH_HIERARCHY           primaryHandle;
    TPM2B_SENSITIVE_CREATE      inSensitive;
    TPM2B_PUBLIC                inPublic;
    TPM2B_DATA                  outsideInfo;
    TPML_PCR_SELECTION          creationPCR;
} CreatePrimary_In;
*/

/* Table 184 - Definition of TPM2B_PUBLIC Structure
typedef struct {
    UINT16      size;           // size of publicArea
    TPMT_PUBLIC publicArea;     // the public area 
} TPM2B_PUBLIC;
*/

/* Table 131 - Definition of TPM2B_SENSITIVE_DATA Structure 

typedef struct {
    UINT16      size;
    BYTE        buffer[MAX_SYM_DATA];   // the keyed hash private data structure
} SENSITIVE_DATA_2B;

typedef union {
    SENSITIVE_DATA_2B t;
    TPM2B             b;
} TPM2B_SENSITIVE_DATA;
*/

/* Table 132 - Definition of TPMS_SENSITIVE_CREATE Structure <IN> 

typedef struct {
    TPM2B_AUTH                  userAuth;       // the USER auth secret value
    TPM2B_SENSITIVE_DATA        data;           // data to be sealed 
} TPMS_SENSITIVE_CREATE;
*/

/* Table 133 - Definition of TPM2B_SENSITIVE_CREATE Structure <IN, S> 

typedef struct {
    UINT16                      size;           // size of sensitive in octets (may not be zero)
    TPMS_SENSITIVE_CREATE       sensitive;      // data to be sealed or a symmetric key value.
} TPM2B_SENSITIVE_CREATE;
*/

    auto start = std::chrono::high_resolution_clock::now();

    // set up the createprimary in parameters
    in.primaryHandle = TPM_RH_ENDORSEMENT;

    in.outsideInfo.t.size = 0;
    in.creationPCR.count = 0;

    TPMT_PUBLIC& tpmt_public=in.inPublic.publicArea;
    tpmt_public.type = TPM_ALG_ECC;
    tpmt_public.nameAlg = TPM_ALG_SHA256;

    tpmt_public.objectAttributes.val = TPMA_OBJECT_FIXEDTPM |
				       TPMA_OBJECT_FIXEDPARENT |
				       TPMA_OBJECT_SENSITIVEDATAORIGIN |
				       TPMA_OBJECT_USERWITHAUTH |
                                       TPMA_OBJECT_NODA |
				       TPMA_OBJECT_RESTRICTED |
				       TPMA_OBJECT_DECRYPT;

    tpmt_public.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;

    tpmt_public.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    tpmt_public.parameters.eccDetail.kdf.details.mgf1.hashAlg = 0;

    tpmt_public.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
    tpmt_public.parameters.eccDetail.symmetric.keyBits.aes = 128;
    tpmt_public.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;

    tpmt_public.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
    tpmt_public.parameters.eccDetail.scheme.details.anySig.hashAlg = 0;

    tpmt_public.unique.ecc.x.t.size = 32;	
    memset(&tpmt_public.unique.ecc.x.t.buffer, 0, 32);	
    tpmt_public.unique.ecc.y.t.size = 32;	
    memset(&tpmt_public.unique.ecc.y.t.buffer, 0, 32);	
   
    in.inSensitive.sensitive.userAuth.t.size = 0;
    in.inSensitive.sensitive.data.t.size = 0;

    tpmt_public.authPolicy.t.size = sizeof(iwgPolicy);
    memcpy(tpmt_public.authPolicy.t.buffer, iwgPolicy, sizeof(iwgPolicy));

    // call TSS to execute the command
	rc = TSS_Execute(tss_context,
			(RESPONSE_PARAMETERS *)out,
			(COMMAND_PARAMETERS *)&in,
			NULL,
			TPM_CC_CreatePrimary,
			TPM_RS_PW, NULL, 0, // Password auth., no password
			TPM_RH_NULL, NULL, 0,
			TPM_RH_NULL, NULL, 0,
			TPM_RH_NULL, NULL, 0); // End of list of session 3-tuples
	if (rc != 0)
    {
	    report_tpm_error(rc,"create_primary: failed");
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto dur = end - start;
    auto i_micros = std::chrono::duration_cast<std::chrono::microseconds>(dur);
    os << "create_primary_ec_ek : TPM2_CreatePrimary : " << std::dec << i_micros.count() << std::hex << '\n';


/* CreatePrimary_Out data structure
    typedef struct {
        TPM_HANDLE          objectHandle;
        TPM2B_PUBLIC        outPublic;
        TPM2B_CREATION_DATA creationData;
        TPM2B_DIGEST        creationHash;
        TPMT_TK_CREATION    creationTicket;
        TPM2B_NAME          name;
    } CreatePrimary_Out;
*/    
    return rc;
}
