/********************************************************************************
* File:        Clock_utils.h
* Description: Utilities for using chrono for dates, times and timing
*
* Created:     Monday 8 October 2018
*
* Copyright:   University of Surrey 2018
*
********************************************************************************/

#pragma once

#include <utility>
#include <vector>
#include <iostream>
#include <iomanip>
#include <chrono>

template<typename Clock, typename Dur=std::chrono::microseconds>
class Timer 
{
public:
    using Rep=typename Dur::rep;
    using Period=typename Dur::period;
    Timer() : start(Clock::now()){}
    void reset() {start=Clock::now();}
    Rep get_duration() {
        Dur d=std::chrono::duration_cast<Dur>(Clock::now()-start);
        return d.count();}

private:
    typename Clock::time_point start;
};

// A set of microsecond timers
using Steady_timer=Timer<std::chrono::steady_clock>;
using System_timer=Timer<std::chrono::system_clock>;
using High_res_timer=Timer<std::chrono::high_resolution_clock>;

// A microsecond timer returning a float
using F_microseconds=std::chrono::duration<float,std::micro>;
using F_timer_mu=Timer<std::chrono::steady_clock,F_microseconds>;

// A millisecond timer returning a float
using F_milliseconds=std::chrono::duration<float,std::milli>;
using F_timer_ms=Timer<std::chrono::steady_clock,F_milliseconds>;

template<typename Rep>
class Timing_data
{
public:
    Timing_data()=delete;
    Timing_data(std::string  str,Rep t) : label_(std::move(str)), time_(t) {}
    Timing_data(Timing_data const&)=default;
    Timing_data(Timing_data&&)=default;
    std::string label() const {return label_;}
    Rep time() const {return time_;}
    ~Timing_data()=default;
private:
    std::string label_;
    Rep time_;
};

template<typename Rep>
class Timings
{
public:
    using Timing_set=std::vector<Timing_data<Rep>>;
    using Time_val=Rep;
    Timings()=default;
    Timings(Timings const&)=default;
    Timings(Timings&&)=default;
    void add(std::string str, Rep t);
    size_t size() const {return timings_.size();}
    Timing_set get_timings();
    void write_timings(std::ostream& os) const;
    ~Timings()=default;
private:
    Timing_set timings_;
};

template<typename Rep>
void Timings<Rep>::add(std::string str, Rep t)
{
    timings_.emplace_back(str,t);
}

template<typename Rep>
typename Timings<Rep>::Timing_set Timings<Rep>::get_timings()
{
   	Timings<Rep>::Timing_set tim(std::move(timings_));

	return tim; 
}

template<typename Rep>
void Timings<Rep>::write_timings(std::ostream& os) const
{
    auto prec=os.precision();
    os << '\n' << std::setprecision(8); // Large enough for (almost) all timings
                                        // to be output as fixed
    for(auto td : timings_)
    {
        os << td.label() << '\t' << td.time() << '\n';
    }
    os << std::flush << std::setprecision(prec);
}

std::string time_point_to_string(
const std::chrono::system_clock::time_point& tp
);

