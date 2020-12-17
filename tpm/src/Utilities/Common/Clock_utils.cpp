/**********************************************************************
* File:        Clock_utils.cpp
* Description: Utilities for using chrono for dates, times and timing
*
* Author:      Chris Newton
* Created:     Monday 8 October 2018
*
* (C) Copyright 2018
*
**********************************************************************/

#include "Clock_utils.h"

std::string time_point_to_string(const std::chrono::system_clock::time_point &tp)
{
    // convert to system time:
    auto t = std::chrono::system_clock::to_time_t(tp);
    std::string ts = std::ctime(&t);// convert to calendar time
    ts.resize(ts.size() - 1);// skip trailing newline
    return ts;
}
