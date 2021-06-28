/*******************************************************************************
* File:        Tss_includes.h
* Description: Include file to use with TSS, disables warnings from TSS files
*
* Author:      Chris Newton
*
* Created:     Monday 20 August 2018
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

// This removes most of the warnings from C++ due to the use of the TSS C headers
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#if defined(IBM_TSS)
#include <tss2/tss.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssutils.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>
#include <tss2/tsscrypto.h>
#include <tss2/tsstransmit.h>
#include <tssproperties.h>
using TSS_RC=TPM_RC;  // Use this for shared routines
using TSS_TPMA_OBJECT=uint32_t; // TPMA_OBJECT.val
#elif defined(INTEL_TSS)
#include <tss2_sys.h>
#include <tss2_tcti_device.h>
#include <tss2_tcti_mssim.h>
#define TPM_ALG_ECC TPM2_ALG_ECC	// Fix up differences :-(
#define TPM_ST_ATTEST_QUOTE TPM2_ST_ATTEST_QUOTE
#define TPM_ST_ATTEST_TIME TPM2_ST_ATTEST_TIME
#define TPM_ST_ATTEST_CERTIFY TPM2_ST_ATTEST_CERTIFY
#define TPMA_OBJECT_SIGN_ENCRYPT  TPMA_OBJECT_SIGN_
using TSS_RC=TSS2_RC;
using TSS_TPMA_OBJECT=TPMA_OBJECT;
#else
#error "Invalid TSS type"
#endif
#pragma GCC diagnostic pop
