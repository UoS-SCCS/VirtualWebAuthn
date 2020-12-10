/******************************************************************************
* File:        Make_persistent_key.h
* Description: Use TPM2_EvictControl to make a key persistent
*
* Author:      Chris Newton
*
* Created:     Sunday 6 May 2018
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
*
******************************************************************************/

#pragma once

#include <cstring>
#include "Tss_includes.h"


TPM_RC make_key_persistent(
TSS_CONTEXT* tssContext,
TPMI_RH_PROVISION   auth,
TPM_HANDLE key_handle,
TPM_HANDLE persistent_handle
);

TPM_RC remove_persistent_key(
TSS_CONTEXT* tssContext,
TPMI_RH_PROVISION   auth,
TPM_HANDLE persistent_handle
);
