/*******************************************************************************
* File:        Tpm_utils.h
* Description: TPM utilities (not dependent on the Tpm_daa class)
*
* Author:      Chris Newton
*
* Created:     Thursday 21 June 2018
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
