/***************************************************************************
* File:        Tpm_param.h
* Description: Tpm parameters used throughout the TPM code
*
* Author:      Chris Newton
* Created:     Monday 15 October 2018
*
* (C) Copyright 2018, University of Surrey.
*
**********************************************************************/

#pragma once

#include <string>
#include "Tss_includes.h"
#include "Byte_buffer.h"

const std::string code_version("TPM WebAuthn Experiments Version 0.1");

const std::string platform_auth("p1atf0rmPwd");
const std::string endorsement_auth("end0rseMe");
const std::string storage_auth("myPassw0rd");
const std::string ecdsa_auth("5cdsaPwd");

// The application PCR, we will initialise this as the TPM is provisioned
// This PCR handle should be typed as TPMI_DH_PCR, but this is a UINT32, so use
// that here to avoid dragging in the TSS headers (from IBM TSS, or Intel TSS)
static const uint32_t app_pcr_handle=23;
// Data for provisioning PCR 23
static const Byte_buffer pcr_str("Some arbitrary data for a PCR");
static const Byte_buffer pcr_expected(Hex_string("dec619c7fb02ea23706364c4984a00227659d413626ae7834c37cc258c1f23ef"));
static const Byte_buffer quote_digest_expected(Hex_string("0c67da2ea50ef73874d19d3688e662abacaf20bc69f2bbc9ce2434f012d1e733"));

static const uint32_t ek_persistent_handle=0x810100c0;  

// TCG Infrastructure Work Group (IWG) default EK primary key policy
static const unsigned char iwgPolicy[] = {
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
    0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
    0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
};

static const uint32_t srk_persistent_handle=0x810100c8;  
