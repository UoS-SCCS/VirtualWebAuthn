/******************************************************************************
* File:        Make_key_persistent.cpp
* Description: Use TPM2_EvictControl to make a key persistent
*
* Author:      Chris Newton
*
* Created:     Sunday 6 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/
#include <cstring>
#include "Tss_includes.h"
#include "Tpm_error.h"

TPM_RC make_key_persistent(
TSS_CONTEXT* tssContext,
TPMI_RH_PROVISION   auth,
TPM_HANDLE key_handle,
TPM_HANDLE persistent_handle
)
{
    TPM_RC  rc = 0;
    EvictControl_In in;

/*
typedef struct {
    TPMI_RH_PROVISION   auth;
    TPMI_DH_OBJECT      objectHandle;
    TPMI_DH_PERSISTENT  persistentHandle;
} EvictControl_In;
*/

    in.auth = auth;
    in.objectHandle = key_handle;
    in.persistentHandle = persistent_handle;
    /* call TSS to execute the command */
        rc = TSS_Execute(tssContext,
                         NULL, 
                         (COMMAND_PARAMETERS *)&in,
                         NULL,
                         TPM_CC_EvictControl,
                         TPM_RS_PW, NULL, 0,
                         TPM_RH_NULL, NULL, 0);
        if (rc != 0)
        {            
            report_tpm_error(rc, "ERROR: evictcontrol: failed");
        }

    return rc;
}

TPM_RC remove_persistent_key(
TSS_CONTEXT* tssContext,
TPMI_RH_PROVISION   auth,
TPM_HANDLE persistent_handle
)
{
    return make_key_persistent(tssContext,auth,persistent_handle,persistent_handle);
}
