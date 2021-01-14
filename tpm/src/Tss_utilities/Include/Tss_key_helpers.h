/*****************************************************************************
* File:        Tss2_key_helpers.h
* Description: Helper definitions for key handling in Tss2 using C++
*
* Author:      Chris Newton
*
* Created:     Sunday 1 August 2020
*
* (C) Copyright 2020, Christopher J.P. Newton, all rights reserved.
*
*****************************************************************************/
#pragma once

#include "Tss_includes.h"

// Definitions for useful key properties see Trusted Computing Platforms, TPM
// 2.0 in Context. It is assumed that other object properties can be added as
// desired. Any properties not mentiioned are CLEAR
const TSS_TPMA_OBJECT obj_fixed=TPMA_OBJECT_FIXEDTPM |
		TPMA_OBJECT_FIXEDPARENT;
// See page 282
const TSS_TPMA_OBJECT obj_primary=obj_fixed |
        TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_NODA |
		TPMA_OBJECT_RESTRICTED |
		TPMA_OBJECT_DECRYPT;
// See pages 286 and 288
const TSS_TPMA_OBJECT obj_storage=obj_fixed |
	        TPMA_OBJECT_RESTRICTED |
	        TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_STCLEAR |
		TPMA_OBJECT_DECRYPT;
const TSS_TPMA_OBJECT obj_certify=obj_fixed |
		TPMA_OBJECT_RESTRICTED |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_SIGN;
// User's signng key created inside TPM - add other properties as necessary
const TSS_TPMA_OBJECT obj_signing_tpm=TPMA_OBJECT_SENSITIVEDATAORIGIN |
							  TPMA_OBJECT_SIGN;
// User's signng key created outside TPM - add other properties as necessary
const TSS_TPMA_OBJECT obj_signing_ext=TPMA_OBJECT_SIGN;
// User's assymetric encryption/decryption key created inside TPM - add
// other properties as necessary
const TSS_TPMA_OBJECT obj_binding_tpm=TPMA_OBJECT_SENSITIVEDATAORIGIN |
							  TPMA_OBJECT_DECRYPT;
// User's assymetric encryption/decryption key created inside TPM - add
// other properties as necessary
const TSS_TPMA_OBJECT obj_binding_ext=TPMA_OBJECT_DECRYPT;

