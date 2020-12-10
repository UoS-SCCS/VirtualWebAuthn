/******************************************************************************
* File:        Flush_context.h
* Description: Use TPM2_FlushContext to remove an object from transient memory
*
* Author:      Chris Newton
*
* Created:     Sunday 6 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

#pragma once

#include "Tss_includes.h"

TPM_RC flush_context(
TSS_CONTEXT* tssContext,
TPMI_DH_CONTEXT handle
);
