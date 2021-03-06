/******************************************************************************
* File:        Create_primary_rsa_key.cpp
* Description: Create a primary RSA key in the given hierarchy
*
* Author:      Chris Newton
*
* Created:     Thursday 5 April 2018
* Upadted:     Thursday 10 December 2020
*
* Closely modelled on example code from the IBM TSS software
*
* (C) Copyright 2018-2020, University of Surrey, all rights reserved.
*
******************************************************************************/

#include <sstream>
#include <cstring>
#include <chrono>
#include "Ibmtss_helpers.h"
#include "Tpm_timer.h"
#include "Tpm_param.h"
#include "Tpm_error.h"
#include "Create_primary_rsa_key.h"

// Create a primary key in the given hierarchy
TPM_RC create_primary_rsa_key(
TSS_CONTEXT* tss_context,
TPMI_RH_HIERARCHY primary_handle,
uint32_t attributes,
Byte_buffer policy,
CreatePrimary_Out* out
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
    /* Table 183 - Definition of TPMT_PUBLIC Structure

    typedef struct {
        TPMI_ALG_PUBLIC     type;                   // "algorithm" associated with this object
        TPMI_ALG_HASH       nameAlg;                // algorithm used for computing the Name of the object
        TPMA_OBJECT         objectAttributes;       // attributes that, along with type, determine the manipulations of this object
        TPM2B_DIGEST        authPolicy;             // optional policy for using this key
        TPMU_PUBLIC_PARMS   parameters;             // the algorithm or structure details
        TPMU_PUBLIC_ID      unique;                 // the unique identifier of the structure
    } TPMT_PUBLIC;
    */

    /* Table 181 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> 

    typedef union {
    #ifdef TPM_ALG_KEYEDHASH
        TPMS_KEYEDHASH_PARMS        keyedHashDetail;        // TPM_ALG_KEYEDHASH 
    #endif
    #ifdef TPM_ALG_SYMCIPHER
        TPMS_SYMCIPHER_PARMS        symDetail;              // TPM_ALG_SYMCIPHER
    #endif
    #ifdef TPM_ALG_RSA
        TPMS_RSA_PARMS              rsaDetail;              // TPM_ALG_RSA
    #endif
    #ifdef TPM_ALG_ECC
        TPMS_ECC_PARMS              eccDetail;              // TPM_ALG_ECC 
    #endif
        TPMS_ASYM_PARMS             asymDetail;             // common scheme structure for RSA and ECC keys
    } TPMU_PUBLIC_PARMS;

    */

    /* Table 179 - Definition of {RSA} TPMS_RSA_PARMS Structure

    typedef struct {
        TPMT_SYM_DEF_OBJECT symmetric;      // for a restricted decryption key, shall be set to a supported symmetric algorithm, key size, and mode.
        TPMT_RSA_SCHEME     scheme;         // for an unrestricted signing key, shall be either TPM_ALG_RSAPSS TPM_ALG_RSASSA or TPM_ALG_NULL 
        TPMI_RSA_KEY_BITS   keyBits;        // number of bits in the public modulus
        UINT32              exponent;       // the public exponent
    } TPMS_RSA_PARMS;

    typedef struct {
        TPMI_ALG_SYM_OBJECT algorithm;      // selects a symmetric block cipher
        TPMU_SYM_KEY_BITS   keyBits;        // the key size 
        TPMU_SYM_MODE       mode;           // default mode 
    } TPMT_SYM_DEF_OBJECT;

    */
    /* Table 128 - Definition of TPMT_SYM_DEF_OBJECT Structure

    typedef struct {
        TPMI_ALG_SYM_OBJECT algorithm;      // selects a symmetric block cipher
        TPMU_SYM_KEY_BITS   keyBits;        // the key size 
        TPMU_SYM_MODE       mode;           // default mode 
    } TPMT_SYM_DEF_OBJECT;

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
    *//* command line argument defaults 
        objectAttributes.val = 0;
        objectAttributes.val |= TPMA_OBJECT_NODA;
        objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
        objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
        objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
        objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
        objectAttributes.val |= TPMA_OBJECT_DECRYPT;
        objectAttributes.val &= ~TPMA_OBJECT_SIGN;
        objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
        objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
    */

    in.primaryHandle=primary_handle;
    in.inSensitive.sensitive.userAuth.t.size = 0;
    in.inSensitive.sensitive.data.t.size = 0;

    // construct the template using the default IWG template 
    TPMT_PUBLIC& tpmt_public=in.inPublic.publicArea;
    tpmt_public.type = TPM_ALG_RSA;
    tpmt_public.nameAlg = TPM_ALG_SHA256;
    tpmt_public.objectAttributes.val=attributes;
/*    tpmt_public.objectAttributes.val = TPMA_OBJECT_FIXEDTPM |
				       TPMA_OBJECT_FIXEDPARENT |
    			       TPMA_OBJECT_SENSITIVEDATAORIGIN |
				       TPMA_OBJECT_USERWITHAUTH |
                       TPMA_OBJECT_RESTRICTED |
                       TPMA_OBJECT_NODA |
				       TPMA_OBJECT_DECRYPT;
*/

    tpmt_public.authPolicy=bb_to_tpm2b<TPM2B_DIGEST>(policy);

    tpmt_public.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    tpmt_public.parameters.rsaDetail.symmetric.keyBits.aes = aes_key_bits;
    tpmt_public.parameters.rsaDetail.symmetric.mode.aes=TPM_ALG_CFB;
    tpmt_public.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    tpmt_public.parameters.rsaDetail.keyBits = 2048;
    tpmt_public.parameters.rsaDetail.exponent = 0;
    tpmt_public.unique.rsa.t.size = 0;

    in.outsideInfo.t.size = 0;
    in.creationPCR.count = 0;
    rc = TSS_Execute(tss_context,
            (RESPONSE_PARAMETERS *)out,
            (COMMAND_PARAMETERS *)&in,
            NULL,
            TPM_CC_CreatePrimary,
            TPM_RS_PW, NULL, 0,     // Password auth., no password
            TPM_RH_NULL, NULL, 0);  // End of list of session 3-tuples
    if (rc != 0)
    {
        throw(Tpm_error("create primary rsa key failed"));
    }

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

