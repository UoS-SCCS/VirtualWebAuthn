/*****************************************************************************
* File:        Byte_array.h
* Description: Data structures used for interfacing with the Python code
*
* Author:      Chris Newton
*
* Created:     Friday 11 December 2020
*
* (C) Copyright 2020, University of Surrey, all rights reserved.
*
*****************************************************************************/

#pragma once

#include "Byte_buffer.h"

struct Byte_array
{
	uint16_t size{0};
	Byte* data{nullptr};
};

void copy_byte_array(Byte_array& lhs, Byte_array const& rhs);

void release_byte_array(Byte_array& ba);

Byte_buffer byte_array_to_bb(Byte_array const& ba);

void bb_to_byte_array(Byte_array& ba, Byte_buffer const& bb);

