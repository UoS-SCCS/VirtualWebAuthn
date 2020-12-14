/******************************************************************************
* File:        Marshal_public_data.h
* Description: Marshal a key's data 
*
* Author:      Chris Newton
*
* Created:     Sunday 27 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

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
