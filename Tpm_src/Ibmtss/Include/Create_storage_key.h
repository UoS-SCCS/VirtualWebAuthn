/******************************************************************************
* File:        Create_storage_key.h
* Description: Create an an ECC storage key
*
* Author:      Chris Newton
*
* Created:     Sunday 13 December 2020
*
* (C) Copyright 2020, University of Surrey, all rights reserved.
*
******************************************************************************/

#pragma once

#include <iostream>
#include <string>
#include "Byte_buffer.h"
#include "Tss_includes.h"

TPM_RC create_storage_key(
TSS_CONTEXT* tssContext,
TPM_HANDLE parent_key_handle,
std::string const& auth,
Create_Out* out	
);

