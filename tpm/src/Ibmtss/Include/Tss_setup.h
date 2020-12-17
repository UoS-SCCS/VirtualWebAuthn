/******************************************************************************
* File:        Tss_setup.h
* Description: Routines used to set up the TPM
*
* Author:      Chris Newton
*
* Created:     Friday 29 June 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

#pragma once

#include <memory>
#include <string>
#include <iostream>
#include "Tss_includes.h"
#include "Tss_param.h"

enum class Tpm_type {unset,simulator,device};
#if defined(IBM_TSS)
class Tss_setup
{
public:
	Tss_setup()=delete;
	explicit Tss_setup(Tpm_type type) : t(type), 
                        data_dir(Tss_default::data_dir),
                        encrypt_sessions(Tss_default::encrypt_sessions),
                        trace_level(Tss_default::trace_level) {}
	Tpm_type t;
    // default options for any (either) interface
	Tss_property data_dir;
	Tss_property encrypt_sessions;
	Tss_property trace_level;

    virtual TPM_RC set_properties(TSS_CONTEXT* context) const;
	virtual void put(std::ostream& os) const;
    virtual ~Tss_setup(){}
};

using Setup_ptr=std::unique_ptr<Tss_setup>;

class Simulator_setup : public Tss_setup
{
public:
	Simulator_setup(): Tss_setup(Tpm_type::simulator),
                        sim_interface(Tss_default::sim_interface),
                        server_name(Tss_default::server_name),
                        command_port(Tss_default::command_port),
                        platform_port(Tss_default::platform_port),
                        server_type(Tss_default::server_type)
                        {}
    // Simulator options
    Tss_property sim_interface;
	Tss_property server_name;
	Tss_property command_port;
	Tss_property platform_port;
	Tss_property server_type;
    TPM_RC set_properties(TSS_CONTEXT* context) const;
    void put(std::ostream& os) const;
    ~Simulator_setup(){}
};

class Device_setup : public Tss_setup
{
public:
	Device_setup(): Tss_setup(Tpm_type::device),
	                hw_interface(Tss_default::hw_interface),
	                tpm_device(Tss_default::tpm_device) {}
    // Hardware options
	Tss_property hw_interface;
	Tss_property tpm_device;

    TPM_RC set_properties(TSS_CONTEXT* context) const;
	void put(std::ostream& os) const;
    ~Device_setup(){}
};

std::pair<TPM_RC,TSS_CONTEXT*> set_new_context(Tss_setup const& tps);

Tpm_type tpm_type(TSS_CONTEXT* tss_context);

#endif