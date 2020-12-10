/**********************************************************************
* File:        Io_utils.cpp
* Description: I/O utilities
*
* Author:      Chris Newton
* Created:     Wednesday 1 May 2013
*
* (C) Copyright 2013, Hewlett-Packard Ltd, all rights reserved.
*
**********************************************************************/

#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <string>
#include <cctype>
#include <algorithm>
#include "Io_utils.h"

std::string make_filename(
std::string const& baseDir,
std::string const& name
)
{
    std::string fName=baseDir+dirSep+name;
    // Now fix up the directory seperators as appropriate
    std::string::size_type pos=0;
    while ((pos=fName.find(altDirSep,pos))!=std::string::npos) {
        fName.replace(pos,1,1,dirSep);
    }	
    return fName;
}

void eat_white(std::istream& is)
{
    char c;
    while (std::isspace(is.peek())!=0) {
            is.get(c);
    }
}

std::string str_tolower(
std::string const& str
)
{
    std::string s{str};
    std::transform(s.begin(), s.end(), s.begin(), 
        [](unsigned char c){ return std::tolower(c); });
    return s;
}

void print_buffer(
std::ostream& os,
const uint8_t* buf,
const size_t len,
bool remove_leading
)
{
    if (len==0) {
        os << "buffer empty";
        return;
    }
    std::ios oldState(nullptr);
    oldState.copyfmt(os);
    os << std::setfill('0') << std::hex;
    if (remove_leading) {
        if (buf[0]!=0) {
            os << 0+buf[0];
        }
    } else {
            os << std::setw(2) << 0 + buf[0];
    } 
    for (size_t i = 1; i < len; ++i) {
        os << std::setw(2) << 0 + buf[i];	// 0 + used to force conversion to an integer for printing
    }

    os.copyfmt(oldState);
}
