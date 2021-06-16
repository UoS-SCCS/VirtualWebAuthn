/***************************************************************************
* File:        Tpm_initialisation.cpp
* Description: TPM initialisation routines
*
* Author:      Chris Newton
*
* Created:     Saturday 25 May 2019
*
* (C) Copyright 2019, University of Surrey.
*
****************************************************************************/

#include <iostream>
#include <cstring>
#include <ctime>
#include <string>
#include "Tss_includes.h"
#include "Io_utils.h"
#include "Logging.h"
#include "Tpm_error.h"
#include "Tpm_utils.h"
#include "Tpm_param.h"
#include "Tpm_timer.h"
#include "Sha.h"
#include "Make_key_persistent.h"
#include "Flush_context.h"
#include "Tpm_initialisation.h"

TPM_RC powerup(Tss_setup const &tps)
{
    TPM_RC rc = 0;


    TSS_CONTEXT *tmp_context = nullptr;// powerup seems to leave the TSS_CONTEXT in a funny state,
      // so use a temporary one and then delete it.

    auto nc = set_new_context(tps);
    rc = nc.first;
    if (rc == 0) {
        tmp_context = nc.second;
        rc = TSS_TransmitPlatform(tmp_context, TPM_SIGNAL_POWER_OFF, "TPM2_PowerOffPlatform");
    }
    if (rc == 0) {
        rc = TSS_TransmitPlatform(tmp_context, TPM_SIGNAL_POWER_ON, "TPM2_PowerOnPlatform");
    }
    if (rc == 0) {
        rc = TSS_TransmitPlatform(tmp_context, TPM_SIGNAL_NV_ON, "TPM2_NvOnPlatform");
    }

    TPM_RC rc1 = TSS_Delete(tmp_context);
    if (rc == 0) {
        rc = rc1;
    }

    return rc;
}

TPM_RC startup(TSS_CONTEXT *tss_context)
{
    TPM_RC rc = 0;

    Startup_In in;
    in.startupType = TPM_SU_CLEAR;
    rc = TSS_Execute(tss_context,
      nullptr,
      reinterpret_cast<COMMAND_PARAMETERS *>(&in),
      nullptr,
      TPM_CC_Startup,
      TPM_RH_NULL,
      NULL,
      0);

    return rc;
}

TPM_RC shutdown(TSS_CONTEXT *tss_context)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    Shutdown_In in;
    in.shutdownType = TPM_SU_CLEAR;
    rc = TSS_Execute(tss_context,
      nullptr,
      reinterpret_cast<COMMAND_PARAMETERS *>(&in),
      nullptr,
      TPM_CC_Shutdown,
      TPM_RH_NULL,
      NULL,
      0);

    return rc;
}

bool persistent_key_available(TSS_CONTEXT *tss_context, TPM_HANDLE handle)
{
    TPM_RC rc;

    bool key_available = false;

    GetCapability_In in;
    GetCapability_Out out;
    in.capability = TPM_CAP_TPM_PROPERTIES;
    in.property = TPM_PT_HR_PERSISTENT;
    in.propertyCount = 1;
    rc = TSS_Execute(tss_context,
      reinterpret_cast<RESPONSE_PARAMETERS *>(&out),
      reinterpret_cast<COMMAND_PARAMETERS *>(&in),
      nullptr,
      TPM_CC_GetCapability,
      TPM_RH_NULL,
      NULL,
      0);
    if (rc != 0) {
        log(Log_level::error, "persistent_key_available: GetCapability (TPM_PT_HR_PERSISTENT) failed");
        throw(Tpm_error("persistent_key_available: GetCapability (TPM_PT_HR_PERSISTENT) failed"));
    }

    auto ph_count = out.capabilityData.data.tpmProperties.tpmProperty[0].value;
    if (ph_count != 0) {
        auto handles = retrieve_persistent_handles(tss_context, ph_count);
        for (auto h : handles) {
            if (h == handle) {
                key_available = true;
                break;
            }
        }
    }

    return key_available;
}

std::vector<TPM_HANDLE> retrieve_persistent_handles(TSS_CONTEXT *tss_context, uint32_t ph_count)
{
    //!!!!!!!Need to fix this for the case where there is more data
    //!!!!!!!Not needed here as we should only have one, or two persistent handles
    TPM_RC rc = 0;

    log(Log_level::info, "retrieve_persistent_handles");

    std::vector<TPM_HANDLE> handles;

    GetCapability_In in;
    GetCapability_Out out;
    in.capability = TPM_CAP_HANDLES;
    in.property = static_cast<uint32_t>(TPM_HT_PERSISTENT) << 24;
    in.propertyCount = ph_count;
    rc = TSS_Execute(tss_context,
      reinterpret_cast<RESPONSE_PARAMETERS *>(&out),
      reinterpret_cast<COMMAND_PARAMETERS *>(&in),
      nullptr,
      TPM_CC_GetCapability,
      TPM_RH_NULL,
      NULL,
      0);
    if (rc != 0) {
        log(Log_level::error, vars_to_string("retrieve_persistent_handles: ", get_tpm_error(rc)));
        throw(Tpm_error("Tpm_daa: GetCapability (TPM_HT_PERSISTENT) failed"));
    }

    uint32_t h_count = out.capabilityData.data.handles.count;
    for (uint32_t i = 0; i < h_count; ++i) {
        handles.push_back(out.capabilityData.data.handles.handle[i]);
    }

    return handles;
}

TPM_RC make_key_persistent(
  TSS_CONTEXT *tss_context,
  TPM_HANDLE key_handle,
  TPM_HANDLE persistent_handle)
{
    TPM_RC rc = 0;

    rc = make_key_persistent(tss_context, TPM_RH_OWNER, key_handle, persistent_handle);
    if (rc == TPM_RC_NV_DEFINED) {
        TPM_RC rc1 = remove_persistent_key(tss_context, TPM_RH_OWNER, persistent_handle);
        if (rc1 == 0) {
            rc = make_key_persistent(tss_context, TPM_RH_OWNER, key_handle, persistent_handle);
        }
    }
    if (rc != 0) {
        log(Log_level::error, "Unable to make the key persistent, removing it");
        TPM_RC rc1 = flush_context(tss_context, key_handle);
        if (rc1 != 0) {
            log(Log_level::error, vars_to_string("Unable to flush the key, handle: ", std::hex, key_handle));
        } else {
            log(Log_level::error, vars_to_string("Key with handle: ", std::hex, key_handle, " flushed"));
        }
    }

    return rc;
}
