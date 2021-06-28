/*******************************************************************************
* File:        Byte_buffer.cpp
* Description: Implementation of a Byte buffer
*
* Author:      Chris Newton
* Created:     Thursday 1 December 2016
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

#include <cstdint>
#include <cstring>
#include <string>
#include <cctype>
#include <vector>
#include <exception>
#include <stdexcept>
#include <limits>
#include <sstream>
#include <iostream>
#include <iomanip>

#include "Byte_buffer.h"

Byte_buffer::Byte_buffer()
{
    byte_buf_.reserve(initial_reserved_size);
}

Byte_buffer::Byte_buffer(std::initializer_list<Byte> il) : byte_buf_(il) {}

Byte_buffer::Byte_buffer(size_t const sz) : byte_buf_(sz) {}

Byte_buffer::Byte_buffer(size_t const sz, Byte const &b) : byte_buf_(sz, b) {}

Byte_buffer::Byte_buffer(std::string const &str)
{
    size_t buf_size = str.size();
    byte_buf_.resize(buf_size);
    for (size_t i = 0; i < buf_size; ++i) {
        // Assumes the string is made up of 8 bit characters
        byte_buf_[i] = static_cast<Byte>(str[i]);
    }
}

Byte_buffer::Byte_buffer(Bytes bv) : byte_buf_(std::move(bv)) {}


Byte_buffer::Byte_buffer(Hex_string const &hs)
{
    size_t buf_size = hs.size() / 2;
    byte_buf_.resize(buf_size);
    std::string bstr;
    for (size_t i = 0; i < buf_size; ++i) {
        bstr = hs.hex_string().substr(2 * i, 2);
        byte_buf_[i] = static_cast<Byte>(stoul(bstr, nullptr, hex_base));
    }
}

Byte_buffer::Byte_buffer(const Byte *buf, size_t len)
{
    byte_buf_.resize(len);
    memcpy(byte_buf_.data(), buf, len);
}

Byte_buffer Byte_buffer::get_part(size_t start, size_t length) const
{
    if (start + length > byte_buf_.size()) {
        throw(std::runtime_error("Invalid parameters for Byte_buffer::get_part"));
    }

    Byte_buffer bb(length, 0);
    for (size_t i = 0; i < length; ++i) {
        bb[i] = byte_buf_[i + start];
    }

    return bb;
}

void Byte_buffer::set_part(size_t start, Byte_buffer const &part)
{
    if (start + part.size() > byte_buf_.size()) {
        throw(std::runtime_error("Invalid parameters for Byte_buffer::set_part"));
    }

    for (size_t i = 0; i < part.size(); ++i) {
        byte_buf_[i + start] = part[i];
    }
}

Byte_buffer &Byte_buffer::operator+=(Byte_buffer const &b)
{
    size_t current_size = byte_buf_.size();
    size_t b_size = b.size();
    byte_buf_.resize(current_size + b_size);
    memcpy(&byte_buf_[current_size], &b[0], b_size);

    return *this;
}

void Byte_buffer::pad_right(size_t new_length, Byte b)
{
    size_t current_size = byte_buf_.size();
    if (new_length < current_size) {
        throw std::runtime_error("Byte_buffer.pad_right: already longer than this");
    }
    size_t size_delta = new_length - current_size;
    Bytes tmp(size_delta, b);
    memcpy(&byte_buf_[current_size], tmp.data(), size_delta);

}

void Byte_buffer::pad_left(size_t new_length, Byte b)
{
    size_t current_size = byte_buf_.size();
    if (new_length < current_size) {
        throw std::runtime_error("Byte_buffer.pad_left: already longer than this");
    }
    size_t length_delta = new_length - current_size;
    Bytes tmp(new_length, b);
    memcpy(&tmp[length_delta], byte_buf_.data(), current_size);
    byte_buf_ = std::move(tmp);
}


void Byte_buffer::truncate()
{
    while (!byte_buf_.empty() && byte_buf_.back() == 0) {
        byte_buf_.pop_back();
    }
}

std::string Byte_buffer::to_hex_string() const
{
    std::ostringstream os;
    size_t str_length = byte_buf_.size();
    if (str_length == 0) {
        return os.str();
    }

    os << std::setfill('0') << std::hex;
    for (size_t i = 0; i < str_length; ++i) {
        os << std::setw(2) << 0 + byte_buf_[i];// 0 + used to force conversion to an integer for printing
          // otherwise this will print as a character
    }
    return os.str();
}

Byte_buffer operator+(Byte_buffer const &a, Byte_buffer const &b)
{
    Byte_buffer oc(a);
    return oc += b;
}

std::string bb_to_string(Byte_buffer const &bb)
{
    size_t sz = bb.size();
    std::string ochar(sz, '\0');
    memcpy(ochar.data(), bb.cdata(), sz);

    return ochar;
}

Byte_buffer uint16_to_bb(uint16_t ui)
{
    Byte_buffer bb(2, 0);
    bb[0] = static_cast<Byte>(ui / 256);
    bb[1] = static_cast<Byte>(ui % 256);
    return bb;
}

Byte_buffer uint32_to_bb(uint32_t ui)
{
    Byte_buffer bb(4, 0);
    uint32_t ival = ui;
    for (uint32_t i = 0; i < 4; ++i) {
        bb[3 - i] = (ival & 0xff);// NOLINT
        ival >>= 8;// NOLINT
    }
    return bb;
}

Byte_buffer serialise_bb(Byte_buffer const &bb)
{
    Byte_buffer sbb;
    size_t sz = bb.size();
    if (sz > std::numeric_limits<uint16_t>::max()) {
        throw(std::runtime_error("serialise_bb: buffer to big to serialise"));
    }
    sbb.resize(sz + 2);
    sbb[0] = static_cast<uint8_t>(sz / byte_base);
    sbb[1] = static_cast<uint8_t>(sz % byte_base);
    memcpy(&sbb[2], bb.cdata(), sz);

    return sbb;
}

Byte_buffer deserialise_bb(Byte_buffer const &bb)
{
    Byte_buffer dbb;
    size_t sz = byte_base * bb[0] + bb[1];
    // Minimal test for consistency
    if (sz > std::numeric_limits<uint16_t>::max() || bb.size() != sz + 2) {
        throw(std::runtime_error("deserialise_bb: inconsistent buffer size"));
    }
    dbb.resize(sz);
    memcpy(dbb.data(), &bb[2], sz);

    return dbb;
}

Byte_buffer serialise_byte_buffers(std::vector<Byte_buffer> const &bbs)
{
    size_t n_buffers = bbs.size();
    if (n_buffers > std::numeric_limits<uint16_t>::max()) {
        throw(std::runtime_error("serialised_byte_buffers: too many buffers to serialise"));
    }
    Byte_buffer sb;
    sb.push_back(static_cast<uint8_t>(n_buffers / byte_base));
    sb.push_back(static_cast<uint8_t>(n_buffers % byte_base));

    for (size_t i = 0; i < n_buffers; ++i) {
        sb += serialise_bb(bbs[i]);
    }

    return sb;
}

std::vector<Byte_buffer> deserialise_byte_buffers(Byte_buffer const &bb)
{
    size_t bb_size = bb.size();
    if (bb_size < 2) {
        throw(std::runtime_error("deserialise_byte_buffers: inconsistent data in Byte_buffer (too small)"));
    }
    std::vector<Byte_buffer> vbb;
    size_t n_buffers = byte_base * bb[0] + bb[1];
    if (n_buffers > std::numeric_limits<uint16_t>::max()) {
        throw(std::runtime_error("deserialise_byte_buffers: inconsistend data in Byte_buffer (too many buffers)"));
    }
    vbb.resize(n_buffers);
    size_t current_index = 2;
    for (size_t i = 0; i < n_buffers; ++i) {
        size_t sz = bb[current_index] * byte_base + bb[current_index + 1];
        if (sz > std::numeric_limits<uint16_t>::max()) {
            throw(std::runtime_error("deserialise_byte_buffers: failed deserialising a Byte_buffer"));
        }
        vbb[i] = bb.get_part(current_index + 2, sz);
        current_index += sz + 2;
    }
    return vbb;
}

// Reads a Byte_buffer from the input stream. The input should be an even number of hex characters
// terminated with whitespace NOT just with some non-hex character
std::istream &operator>>(std::istream &is, Byte_buffer &bb)
{
    char c;// NOLINT
    std::string hstr(2, '\0');
    Byte b;// NOLINT
    bb.byte_buf_.clear();

    uint8_t i = 0;
    is >> std::ws;// Skip whitespace
    while (is.get(c)) {
        if (std::isspace(c) != 0) {
            break;
        }
        hstr[i++] = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (i == 2) {
            if (std::string::npos != hstr.find_first_not_of("0123456789ABCDEFabcdef")) {
                throw(std::runtime_error("Byte_buffer::operator>>: bad character in input stream"));
            }
            b = static_cast<Byte>(stoul(hstr, nullptr, 16));
            bb.byte_buf_.push_back(b);
            i = 0;
        }
    }
    if (i != 0) {
        throw(std::runtime_error("Byte_buffer::operator>>: odd nuber of characters in input stream"));
    }

    return is;
}

std::ostream &operator<<(std::ostream &os, Byte_buffer const &bb)
{
    os << bb.to_hex_string();

    return os;
}

void print_bb_as_characters(std::ostream &os, Byte_buffer const &bb)
{
    // Remove trailing whitespace
    size_t last_char = bb.size();
    Byte ch;
    do {
        ch = bb[--last_char];
    } while (ch == '\0' || std::isspace(ch) != 0);

    for (size_t i = 0; i <= last_char; ++i) {
        ch = bb[i];
        if (std::isspace(ch) != 0 || std::isprint(ch) != 0) {
            os << ch;
        } else {
            os << '?';
        }
    }
}
