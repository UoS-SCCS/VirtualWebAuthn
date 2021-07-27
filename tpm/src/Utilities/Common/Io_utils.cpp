/*******************************************************************************
* File:        Io_utils.cpp
* Description: I/O utilities
*
* Author:      Chris Newton
* Created:     Wednesday 1 May 2013
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
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <string>
#include <cctype>
#include <cstdlib>
#include <algorithm>
#include "Io_utils.h"

std::string make_filename(
  std::string const &baseDir,
  std::string const &name)
{
    std::string fName = baseDir + dirSep + name;
    // Now fix up the directory seperators as appropriate
    std::string::size_type pos = 0;
    while ((pos = fName.find(altDirSep, pos)) != std::string::npos) {
        fName.replace(pos, 1, 1, dirSep);
    }
    return fName;
}

std::string get_environment_variable(
  std::string const &var,
  std::string def) noexcept
{
    const char *ret = std::getenv(var.c_str());
    return ret != nullptr ? std::string(ret) : std::move(def);
}

void eat_white(std::istream &is)
{
    char c;// NOLINT
    while (std::isspace(is.peek()) != 0) {
        is.get(c);
    }
}

std::string str_tolower(
  std::string const &str)
{
    std::string s{ str };
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

void print_buffer(
  std::ostream &os,
  const uint8_t *buf,
  const size_t len,
  bool remove_leading)
{
    if (len == 0) {
        os << "buffer empty";
        return;
    }
    std::ios oldState(nullptr);
    oldState.copyfmt(os);
    os << std::setfill('0') << std::hex;
    if (remove_leading) {
        if (buf[0] != 0) {
            os << 0 + buf[0];
        }
    } else {
        os << std::setw(2) << 0 + buf[0];
    }
    for (size_t i = 1; i < len; ++i) {
        os << std::setw(2) << 0 + buf[i];// 0 + used to force conversion to an integer for printing
    }

    os.copyfmt(oldState);
}
