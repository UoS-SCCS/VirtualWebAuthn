/*******************************************************************************
* File:        Marshal_data.cpp
* Description: Marshal a key's public data (TPMT_PUBLIC)
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

#include <iostream>
#include "Marshal_data.h"

Byte_buffer marshal_public_data_T(
TPMT_PUBLIC* public_data
)
{
	TSS_RC rc = 0;
	uint16_t size=0;
	uint8_t* buffer=nullptr;
	Byte_buffer result;

	rc=TSS_Structure_Marshal(&buffer,&size,public_data, (MarshalFunction_t)TSS_TPMT_PUBLIC_Marshal);
	if (rc==0)
	{
    	Byte_buffer marshalled_tpmt_public(buffer,size);
		result=marshalled_tpmt_public;
	}
	if (buffer)
		free(buffer);
	return result;
}

Byte_buffer marshal_public_data_B(
TPM2B_PUBLIC* public_data
)
{
	TSS_RC rc = 0;
	uint16_t size=0;
	uint8_t* buffer=nullptr;
	Byte_buffer result;

	rc=TSS_Structure_Marshal(&buffer,&size,public_data, (MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshal);
	if (rc==0)
	{
    	Byte_buffer marshalled_tpm2b_public(buffer,size);
		result=marshalled_tpm2b_public;
	}
	if (buffer)
		free(buffer);
	return result;
}

TSS_RC unmarshal_public_data_B(
Byte_buffer& pd_bb,
TPM2B_PUBLIC* public_data_ptr
)
{
	TSS_RC rc=0;

	Byte* tmp_bb=&pd_bb[0];
	auto tmp_size=static_cast<int32_t>(pd_bb.size());
	rc = TPM2B_PUBLIC_Unmarshal(public_data_ptr, &tmp_bb, &tmp_size, YES);

	return rc;
}


Byte_buffer marshal_private_data_B(
TPM2B_PRIVATE* private_data
)
{
	TSS_RC rc = 0;
	uint16_t size=0;
	uint8_t* buffer=nullptr;
	Byte_buffer result;

	rc=TSS_Structure_Marshal(&buffer,&size,private_data, (MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshal);
	if (rc==0)
	{
    	Byte_buffer marshalled_tpm2b_private(buffer,size);
		result=marshalled_tpm2b_private;
	}
	if (buffer)
		free(buffer);
	return result;
}

TSS_RC unmarshal_private_data_B(
Byte_buffer& pd_bb,
TPM2B_PRIVATE* private_data_ptr
)
{
	TSS_RC rc=0;

	Byte* tmp_bb=&pd_bb[0];
	auto tmp_size=static_cast<int32_t>(pd_bb.size());
	rc = TPM2B_PRIVATE_Unmarshal(private_data_ptr, &tmp_bb, &tmp_size);

	return rc;
}

/*
Byte_buffer marshal_attest_data(
TPMS_ATTEST* attest_data
)
{
	TSS_RC rc = 0;
	uint16_t size=0;
	uint8_t* buffer=NULL;
	Byte_buffer result;

	rc=TSS_Structure_Marshal(&buffer,&size,attest_data, (MarshalFunction_t)TSS_TPMS_ATTEST_Marshal);
	if (rc==0)
	{
    	Byte_buffer marshalled_tpms_attest(buffer,size);
		result=marshalled_tpms_attest;
	}
	if (buffer)
		free(buffer);
	return result;
}
*/

TSS_RC unmarshal_attest_data_B(
Byte_buffer& atd_bb,
TPMS_ATTEST* attest_data_ptr
)
{
	TSS_RC rc=0;
	Byte_buffer padded_data=atd_bb;
	padded_data.pad_right(sizeof(TPMS_ATTEST));
	Byte* tmp_bb=&padded_data[0];
	auto tmp_size=static_cast<int32_t>(atd_bb.size());
	rc = TPMS_ATTEST_Unmarshal(attest_data_ptr, &tmp_bb, &tmp_size);

	return rc;
}
