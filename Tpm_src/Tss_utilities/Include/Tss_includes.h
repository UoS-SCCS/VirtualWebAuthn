/******************************************************************************
* File:        Tss_includes.h
* Description: Include file to use with TSS, disables warnings from TSS files
*
* Author:      Chris Newton
*
* Created:     Monday 20 August 2018
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
*
******************************************************************************/
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
#define TSS_RC TPM_RC   // Use this for shared routines
#elif defined(INTEL_TSS)
#include <tss2_sys.h>
#include <tss2_tcti_device.h>
#include <tss2_tcti_mssim.h>
#define TPM_ALG_ECC TPM2_ALG_ECC	// Fix up differences :-(
#define TPM_ST_ATTEST_QUOTE TPM2_ST_ATTEST_QUOTE
#define TPM_ST_ATTEST_TIME TPM2_ST_ATTEST_TIME
#define TPM_ST_ATTEST_CERTIFY TPM2_ST_ATTEST_CERTIFY
#define TSS_RC TSS2_RC
#else
#error "Invalid TSS type"
#endif
#pragma GCC diagnostic pop
