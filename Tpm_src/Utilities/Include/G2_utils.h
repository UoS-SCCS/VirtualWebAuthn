/***************************************************************************
* File:        G2_utils.h
* Description: Utility functions for the extension field, G2
*
* Author:      Chris Newton
* Created:     Tursday 15 November 2018
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

const size_t g2_coord_component_size=component_size;
const size_t g2_coord_size=2*g2_coord_component_size;
const size_t g2_affine_point_size=2*g2_coord_size;

using G2_coord=std::pair<Byte_buffer,Byte_buffer>;
using G2_point=std::pair<G2_coord,G2_coord>;

Byte_buffer g2_coord_concat(G2_coord const& coord);
G2_coord g2_coord_from_bb(Byte_buffer const& bb);

Byte_buffer g2_point_concat(G2_point const& pt);
G2_point g2_point_from_bb(Byte_buffer const& bb);

Byte_buffer g2_coord_serialise(G2_coord const& coord);
Byte_buffer g2_point_serialise(G2_point const& pt);

G2_coord g2_coord_deserialise(Byte_buffer const& bb);
G2_point g2_point_deserialise(Byte_buffer const& bb);

