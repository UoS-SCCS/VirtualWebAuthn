/***************************************************************************
* File:        TPM_error.h
* Description: Error reporting for TSS
*
* Author:      Chris Newton
*
* Created:     Sunday 20 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once

#include <stdexcept>
#include <string>
#include "Tss_includes.h"

class Tpm_error : public std::runtime_error
{
public:
    explicit Tpm_error(const char* what) : runtime_error(what) {}
};

std::string get_tpm_error(TSS_RC rc);

void report_tpm_error(TSS_RC rc, std::string const& comment);
