/***************************************************************************
* File:        Tpm_defs.h
* Description: Definitions used throughout the DAA code
*
* Author:      Chris Newton
* Created:     Monday 15 October 2018
*
* (C) Copyright 2018, University of Surrey.
*
**********************************************************************/

#pragma once

#include <string>
#include "Clock_utils.h"
#include "Logging.h"

using Tpm_timer=F_timer_mu;
using Timer_data=Timing_data<Tpm_timer::Rep>;
using Tpm_timings=Timings<Tpm_timer::Rep>;

extern Tpm_timings tpm_timings;

