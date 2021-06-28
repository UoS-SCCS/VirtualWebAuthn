/*******************************************************************************
* File:        Logging.cpp
* Description: Routines for logging errors and data
*
* Author:      Chris Newton
* Created:     Monday 15 October 2018
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

#include <iosfwd>
#include <sstream>
#include "Clock_utils.h"
#include "Logging.h"

// Do nothing unless the pointer is reset to a 'real' log.
Log_ptr log_ptr = Log_ptr(new Null_log);

std::ostream &Timed_cout_log::os()
{
    auto tp = std::chrono::system_clock::now();
    std::cout << time_point_to_string(tp) << ": ";
    return std::cout;
}

void Timed_cout_log::write_to_log(std::string str)
{
    auto tp = std::chrono::system_clock::now();
    std::cout << time_point_to_string(tp) << ": " << str << std::flush;
}

File_log::File_log(std::string const &filename)
{
    os_.open(filename.c_str(), std::ios::out);
    if (!os_) {
        throw(std::runtime_error("Unable to open the log file"));
    }
}

File_log::~File_log()
{
    if (os_) {
        os_.close();
    }
}

Timed_file_log::Timed_file_log(std::string const &filename)
{
    os_.open(filename.c_str(), std::ios::out);
    if (!os_) {
        throw(std::runtime_error("Unable to open the log file"));
    }
}

std::ostream &Timed_file_log::os()
{
    auto tp = std::chrono::system_clock::now();
    os_ << time_point_to_string(tp) << ": ";
    return os_;
}

void Timed_file_log::write_to_log(std::string str)
{
    auto tp = std::chrono::system_clock::now();
    os_ << time_point_to_string(tp) << ": " << str << std::flush;
}

Timed_file_log::~Timed_file_log()
{
    if (os_) {
        os_.close();
    }
}

std::string generate_log_number()
{
    // Get current time with native precision
    auto tp = std::chrono::system_clock::now();
    // Convert time_point to 0.1s
    auto duration = std::chrono::duration_cast<std::chrono::duration<int64_t, std::ratio<1, 10>>>(tp.time_since_epoch());
    std::ostringstream oss;
    // Get 0.1s value and find remainder for ~5 year repeat
    const uint32_t five_year_count = 600 * 60 * 24 * 365 * 5;
    oss << duration.count() % five_year_count;

    return oss.str();
}

std::string generate_log_date_time()
{
    // Get current time with native precision
    auto tp = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%Y%m%d-%H%M%S");

    return oss.str();
}

std::string generate_log_filename(
  std::string const &base_dir,
  std::string const &prefix)
{
    std::ostringstream oss;
    oss << base_dir << '/' << prefix << '_' << generate_log_number();

    return oss.str();
}

std::string generate_date_time_log_filename(
  std::string const &base_dir,
  std::string const &prefix)
{
    std::ostringstream oss;
    oss << base_dir << '/' << prefix << '_' << generate_log_date_time();

    return oss.str();
}

void log(Log_level level, std::string const &log_msg)
{
    if (level <= log_ptr->debug_level()) {
        log_ptr->write_to_log(log_msg);
    }
}
