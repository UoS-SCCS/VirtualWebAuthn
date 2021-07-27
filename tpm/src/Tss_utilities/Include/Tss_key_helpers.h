/*******************************************************************************
* File:        Tss2_key_helpers.h
* Description: Helper definitions for key handling in Tss2 using C++
*
* Author:      Chris Newton
*
* Created:     Sunday 1 August 2020
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

