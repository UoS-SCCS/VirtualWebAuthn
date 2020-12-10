/***************************************************************************
* File:        Sha.h
* Description: sha functions
*
* Author:      Chris Newton
* Created:     Sunday 29 March 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once

#include "Byte_buffer.h"

Byte_buffer sha256_bb(Byte_buffer const& bb);
