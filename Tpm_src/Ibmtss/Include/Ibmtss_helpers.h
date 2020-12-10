/*****************************************************************************
* File:        Ibmtss_helpers.h
* Description: Helper routines C++ and Ibmtss
*
* Author:      Chris Newton
*
* Created:     Wedensday 26 August 2020
*
* (C) Copyright 2020, Christopher J.P. Newton, all rights reserved.
*
*****************************************************************************/

#pragma once

#include "Byte_buffer.h"
#include "Tss_includes.h"

template<typename T>
Byte_buffer tpm2b_to_bb(T const& buf)
{
    return Byte_buffer(buf.t.buffer,buf.t.size);
}

template<typename T>
T bb_to_tpm2b(Byte_buffer const& bb)
{
    if (bb.size()>sizeof(T)-2)
    {
        throw(std::runtime_error(
                "Byte_buffer too large for given TPM2B structure"));
    }
    T buf;
    buf.t.size=static_cast<uint16_t>(bb.size());
    memcpy(buf.t.buffer,bb.cdata(),buf.t.size);
    return buf;
}
