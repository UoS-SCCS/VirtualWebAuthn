/*******************************************************************************
* File:        Io_utils.h
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

#pragma once

#include <iostream>
#include <sstream>
#include <string>

// Define the appropriate directory seperators and their opposites
#ifndef _WIN32
//#define _MAX_FNAME 1024
constexpr char dirSep = '/';
constexpr char altDirSep = '\\';
#else
constexpr char dirSep = '\\';
constexpr char altDirSep = '/';
#endif

// Terminal colours
auto constexpr blue = "\33[34m";
auto constexpr red = "\33[31m";
auto constexpr green = "\33[32m";
auto constexpr magenta = "\33[35m";
auto constexpr normal = "\33[0m";

constexpr int maxline = 200;

std::string make_filename(
  std::string const &baseDir,
  std::string const &name);

std::string get_environment_variable(
  std::string const &var,
  std::string def) noexcept;

void eat_white(std::istream &is);

std::string str_tolower(
  std::string const &str);

std::string str_toupper(
  std::string const &str);

void print_hex_byte(
  std::ostream &os,
  uint8_t byte);

void print_buffer(
  std::ostream &os,
  const uint8_t *buf,
  size_t len,
  bool remove_leading);


// Initialiser list version of vars_to_string
// (A,B) - A is carried out first, then B. The result from B is returned
// (os << t, 0) - writes t to the stream and returns 0 to the <int> initializer list
// ... the parameter pack is expanded
template<typename... T>
std::string vars_to_string(const T &... t)
{
    std::ostringstream os;
    (void)std::initializer_list<int>{ (os << t, 0)... };
    return os.str();
}
