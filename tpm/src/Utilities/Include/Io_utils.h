/**********************************************************************
* File:        Io_utils.h
* Description: I/O utilities
*
* Author:      Chris Newton
* Created:     Wednesday 1 May 2013
*
* (C) Copyright 2013
*
**********************************************************************/

#pragma once

#include <iostream>
#include <sstream>
#include <string>

// Define the appropriate directory seperators and their opposites
#ifndef _WIN32
//#define _MAX_FNAME 1024
const char dirSep='/';
const char altDirSep='\\';
#else
const char dirSep='\\';
const char altDirSep='/';
#endif

const int maxline=200;

std::string make_filename(
std::string const& baseDir,
std::string const& name
);

void eat_white(std::istream& is);

std::string str_tolower(
std::string const& str
);

void print_buffer(
std::ostream& os,
const uint8_t* buf,
size_t len,
bool remove_leading
);

template<typename T>
std::string vars_to_string(T const& t)
{
	std::ostringstream os;
	os << t;
	return os.str();
}

template<typename T, typename...Vargs>
std::string vars_to_string(T t, Vargs... args)
{
	std::ostringstream os;
	os << t;
	return os.str()+vars_to_string(args...);
}

