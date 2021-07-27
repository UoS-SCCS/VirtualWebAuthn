/*******************************************************************************
* File:        Hex_string.cpp
* Description: Hex_string class for parameter passing in VANET demonstrator
*              It MUST NOT throw
*
* Author:      Chris Newton
* Created:     Saturday 30 June 2018
*
*
*******************************************************************************/

/*******************************************************************************
*                                                                              *
* (C) Copyright 2020-2021 University of Surrey                                 *
*                                                                              *
* Redistribution and use in source and binary forms, with or without           *
* modification, are permitted provided that the following conditions are met:  *
*                                                                              *
* 1. Redistributions of source code must retain the above copyright notice,    *
* this list of conditions and the following disclaimer.                        *
*                                                                              *
* 2. Redistributions in binary form must reproduce the above copyright notice, *
* this list of conditions and the following disclaimer in the documentation    *
* and/or other materials provided with the distribution.                       *
*                                                                              *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"  *
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE    *
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE   *
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE    *
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR          *
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF         *
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS     *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN      *
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)      *
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE   *
* POSSIBILITY OF SUCH DAMAGE.                                                  *
*                                                                              *
*******************************************************************************/
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
