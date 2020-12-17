/***************************************************************************************
* File:        Get_random_bytes.h
* Description: Get a set of pseudo-random bytes
*
*
* Author:      Chris Newton
* Created:     Wednesay 30 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
***************************************************************************************/
#pragma once

#include <random>
#include "Byte_buffer.h"

using seed_type=std::default_random_engine::result_type;

class Random_byte_generator
{
public:
    explicit Random_byte_generator(seed_type seed=0);
    Byte_buffer operator()(size_t number_of_bytes);

private:
    // Use the C++ PRNG for now
    std::default_random_engine dre;
    std::uniform_int_distribution<uint8_t> rb;
};


Byte_buffer get_random_bytes(
size_t number_of_bytes,
seed_type seed=0
);

