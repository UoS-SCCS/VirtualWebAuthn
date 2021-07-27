/*******************************************************************************
* File:        Tss_setup.cpp
* Description: Routines used to set up the TPM
*
* Author:      Chris Newton
*
* Created:     Friday 29 June 2018
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
		  rc=TSS_SetProperty(nullptr,trace_level.type,trace_level.value);

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
