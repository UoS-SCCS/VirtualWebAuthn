/***************************************************************************
* File:        G1_utils.h
* Description: Utility functions for the base field, G1
*
* Author:      Chris Newton
*
* Created:     Wednesday 28 November 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once 

#include <cstdint>
#include <string>
#include <iostream>
#include <memory>
#include "bnp256_param.h"
#include "Byte_buffer.h"

const size_t g1_coord_size=component_size;
const size_t g1_affine_point_size=2*g1_coord_size;
// Size for uncompressed representation (uncompressed code) + x + y
const size_t g1_uncompressed_point_size=g1_affine_point_size+1;
// Size for compressed representation - (compressed code) + x-coord + 1
// - check this !!!!)
const size_t g1_compressed_point_size=g1_coord_size+2;

using G1_point=std::pair<Byte_buffer,Byte_buffer>;

Byte_buffer g1_point_concat(G1_point const& pt);

Byte_buffer g1_point_uncompressed(G1_point const& pt);

G1_point g1_point_from_bb(Byte_buffer const& bb);

Byte_buffer g1_point_serialise(G1_point const& pt);

G1_point g1_point_deserialise(Byte_buffer const& bb);

