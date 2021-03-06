/******************************************************************************
* File:        Tss_setup.cpp
* Description: Routines used to set up the TPM
*
* Author:      Chris Newton
*
* Created:     Friday 29 June 2018
*
*  (C) Copyright 2018, University of Surrey, all rights reserved.
*
******************************************************************************/

#include <iostream>
#include <string>
//#include "Tpm_error.h"
#include "Tss_setup.h"

void Tss_setup::put(std::ostream& os) const
{
   os << "Base class\n";
}

void Simulator_setup::put(std::ostream& os) const
{
    Tss_setup::put(os);
    os << "Simulator setup class\n";
}

void Device_setup::put(std::ostream& os) const
{
    Tss_setup::put(os);
    os << "Device setup class\n";
}

TPM_RC Tss_setup::set_properties(TSS_CONTEXT* context) const
{
    TPM_RC rc=0;
    // For the moment just set the common setting and ignore the others
    if (trace_level.value != Tss_default::trace_level.value)
		  rc=TSS_SetProperty(NULL,trace_level.type,trace_level.value);

    if (rc==0 && encrypt_sessions.value != Tss_default::encrypt_sessions.value)
		  rc=TSS_SetProperty(context,encrypt_sessions.type,encrypt_sessions.value);

    if (rc==0 && data_dir.value != Tss_default::data_dir.value)
		  rc=TSS_SetProperty(context,data_dir.type,data_dir.value);    
    return rc;
}

TPM_RC Simulator_setup::set_properties(TSS_CONTEXT* context) const
{
    TPM_RC rc=Tss_setup::set_properties(context);
    if (rc==0)  // Set to use the simulator
        rc=TSS_SetProperty(context,sim_interface.type,sim_interface.value);
    // Set the options - override defaults if necessary
    if (rc==0 && command_port.value != Tss_default::command_port.value)
        rc=TSS_SetProperty(context,command_port.type,command_port.value);
    if (rc==0 && platform_port.value != Tss_default::platform_port.value)
        rc=TSS_SetProperty(context,platform_port.type,platform_port.value);
    if (rc==0 && server_type.value != Tss_default::server_type.value)
        rc=TSS_SetProperty(context,server_type.type,server_type.value);
    if (rc==0 && server_name.value != Tss_default::server_name.value)
        rc=TSS_SetProperty(context,server_name.type,server_name.value);
    if (rc==0 && sim_interface.value != Tss_default::sim_interface.value)
        rc=TSS_SetProperty(context,sim_interface.type,sim_interface.value);

    return rc;
}

TPM_RC Device_setup::set_properties(TSS_CONTEXT* context) const
{
    TPM_RC rc=Tss_setup::set_properties(context);
    if (rc==0)  // Set to use the HW TPM
        rc=TSS_SetProperty(context,hw_interface.type,hw_interface.value);
    // Set the options - override defaults if necessary
    if (rc==0 && tpm_device.value != Tss_default::tpm_device.value)
        rc=TSS_SetProperty(context,tpm_device.type,tpm_device.value);
    
    return rc;
}

std::pair<TPM_RC,TSS_CONTEXT*> set_new_context(
Tss_setup const& tps
)
{
    TSS_CONTEXT* context=nullptr;
    TPM_RC rc=TSS_Create(&context);
    if (rc==0)
    {
        rc=tps.set_properties(context);
        if(rc!=0)
        {
            TSS_Delete(context);
            context=nullptr;
        }
    }

    return std::make_pair(rc,context);
}

Tpm_type tpm_type(TSS_CONTEXT* tss_context)
{
  Tpm_type t;
  std::string type(tss_context->tssInterfaceType);
  if (type==Tss_default::sim_interface.value)
    t=Tpm_type::simulator;
  else
    t=Tpm_type::device;
  
  return t;
}
