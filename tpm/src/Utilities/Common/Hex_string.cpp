/******************************************************************************
* File:        Hex_string.cpp
* Description: Hex_string class for parameter passing in VANET demonstrator
*              It MUST NOT throw
*
* Author:      Chris Newton
* Created:     Saturday 30 June 2018
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
*
******************************************************************************/
#include <iostream>
#include "Hex_string.h"

Hex_string::Hex_string(std::string const &str)
{
    if (std::string::npos != str.find_first_not_of("0123456789ABCDEFabcdef")) {
        error_ = "Hex_string: bad character in string constructor - must be hex characters";
    } else {
        try {
            hex_string_ = str;
            size_t n_bytes = str.size() / 2;
            // If necessary append a "0" to the front (MSB) of the string
            if (2 * n_bytes != str.size()) {
                hex_string_ = "0" + hex_string_;
            }
            valid_ = true;
        } catch (...) {
            error_ = "Hex_string: failed to copy input into a new string";
        }
    }
}

std::string Hex_string::hex_string() const
{
    size_t len = hex_string_.size();
    std::string hs(len, 0);
    for (size_t i = 0; i < len; ++i) {
        hs[i]=static_cast<char>(std::tolower(static_cast<unsigned char>(hex_string_[i])));
    }

    return hs;
}

std::string Hex_string::get_last_error() const
{
    return error_;
}
