/*******************************************************************************
* File:        Marshal_public_data.h
* Description: Marshal a key's data 
*
* Author:      Chris Newton
*
* Created:     Sunday 27 May 2018
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

#define TPM_TSS

#include "Tss_includes.h"
#include "Byte_buffer.h"

Byte_buffer marshal_public_data_T(
TPMT_PUBLIC* public_data
);

Byte_buffer marshal_public_data_B(
TPM2B_PUBLIC* public_data
);

TSS_RC unmarshal_public_data_B(
Byte_buffer& pd_bb,
TPM2B_PUBLIC* public_data_ptr
);

Byte_buffer marshal_private_data_B(
TPM2B_PRIVATE* private_data
);

TSS_RC unmarshal_private_data_B(
Byte_buffer& pd_bb,
TPM2B_PRIVATE* private_data_ptr
);

/*
Byte_buffer marshal_attest_data(
TPMS_ATTEST* attest_data
);
*/

TSS_RC unmarshal_attest_data_B(
Byte_buffer& atd_bb,
TPMS_ATTEST* attest_data_ptr
);

#undef TPM_TSS
