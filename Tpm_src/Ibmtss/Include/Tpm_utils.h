/***************************************************************************
* File:        Tpm_utils.h
* Description: TPM utilities (not dependent on the Tpm_daa class)
*
* Author:      Chris Newton
*
* Created:     Thursday 21 June 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once

#include <iostream>
#include <iomanip>
#include <string>
#include "Tss_includes.h"
#include "Openssl_ec_utils.h"
#include "Hex_string.h"
#include "Byte_buffer.h"

Byte_buffer ecc_param_to_bb(TPM2B_ECC_PARAMETER const & ecp);

TPM2B_ECC_PARAMETER ecc_param_from_bb(Byte_buffer const & bb);

TPM2B_SENSITIVE_DATA sensitive_data_from_bb(Byte_buffer const & bb);

Byte_buffer get_ek_from_public_data_bb(Byte_buffer const& ek_pd);

Byte_buffer get_ek_from_public_data(TPM2B_PUBLIC const& tpm2b_ekpd);

G1_point get_daa_key_from_public_data_bb(Byte_buffer const& daa_pd); 

G1_point get_daa_key_from_public_data(TPM2B_PUBLIC const& daa_pd); 

void print_attest_data(
std::ostream& os,
TPMS_ATTEST const& ad
);
