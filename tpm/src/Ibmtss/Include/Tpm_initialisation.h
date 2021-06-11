/***************************************************************************
* File:        Tpm_initialisation.h
* Description: Tpm initialisation routines
*
* Author:      Chris Newton
* Created:     Monday 15 October 2018
*
* (C) Copyright 2018, University of Surrey.
*
**********************************************************************/

#pragma once

#include "Tss_setup.h"

TPM_RC powerup(Tss_setup const& tps);

TPM_RC startup(TSS_CONTEXT* tss_context);

TPM_RC shutdown(TSS_CONTEXT* tss_context);

bool persistent_key_available(TSS_CONTEXT* tss_context,TPM_HANDLE handle);

std::vector<TPM_HANDLE> retrieve_persistent_handles(TSS_CONTEXT* tss_context, uint32_t ph_count);

TPM_RC make_key_persistent(TSS_CONTEXT* tss_context,TPM_HANDLE key_handle,TPM_HANDLE persistent_handle);
