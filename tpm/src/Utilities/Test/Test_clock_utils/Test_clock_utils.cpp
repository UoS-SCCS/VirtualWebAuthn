/********************************************************************************
* File:        Test_clock_utils.cpp
* Description: Program to test the C++ clock classes and the pre-
*              defined timers
*
* Author:      Chris Newton
* Created:     Monday 8 October 2018
*
********************************************************************************/

// Adapted from: http://www.informit.com/articles/article.aspx?p=1881386&seqNum=2 

#include <chrono>
#include <iostream>
#include <iomanip>
#include "Clock_utils.h"

template <typename Clock>
void print_clock_data(
std::ostream& os
)
{
    using namespace std;
    //std::ostream& os=std::cout;

    os << " precision: ";
    // if time unit is less or equal one millisecond
    typedef typename Clock::period Period;// type of time unit
    if (ratio_less_equal<Period,milli>::value) {
       // convert to and print as milliseconds
       typedef typename ratio_multiply<Period,kilo>::type TT;
       os << fixed << double(TT::num)/TT::den
            << " milliseconds" << endl;
    }
    else {
        // print as seconds
        os << fixed << double(Period::num)/Period::den << " seconds" << endl;
    }
    os << " is_steady: " << boolalpha << Clock::is_steady << endl;
}

int main()
{
    std::cout << "Testing C++ clocks\n";
    std::cout << "  Time now: "
              << time_point_to_string(std::chrono::system_clock::now())
              << std::endl;

    std::cout << "system_clock: " << std::endl;
    print_clock_data<std::chrono::system_clock>(std::cout);
    std::cout << "\nhigh_resolution_clock: " << std::endl;
    print_clock_data<std::chrono::high_resolution_clock>(std::cout);
    std::cout << "\nsteady_clock: " << std::endl;
    print_clock_data<std::chrono::steady_clock>(std::cout);

    // print the epoch of this system clock:
    std::chrono::system_clock::time_point tp;
    std::cout << "     epoch: " << time_point_to_string(tp) << std::endl;

    // print current time:
    tp = std::chrono::system_clock::now();
    std::cout << "       now: " << time_point_to_string(tp) << std::endl;

    // print minimum time of this system clock:
    tp = std::chrono::system_clock::time_point::min();
    std::cout << "       min: " << time_point_to_string(tp) << std::endl;

    // print maximum time of this system clock:
    tp = std::chrono::system_clock::time_point::max();
    std::cout << "       max: " << time_point_to_string(tp) << std::endl;

    // define type for durations that represent day(s):
    typedef std::chrono::duration<int,std::ratio<3600*24>> Days;

    // process the epoch of this system clock
    std::chrono::time_point<std::chrono::system_clock> tpsc;
    std::cout << "     epoch: " << time_point_to_string(tpsc) << std::endl;

    // add one year (hoping it is valid and not a leap year)
    tpsc += std::chrono::hours(24*365);
    std::cout << " +365 days: " << time_point_to_string(tpsc) << std::endl;

    // add 1 year (hoping it is valid and ignoring leap years)
    tpsc += std::chrono::duration<int,std::ratio<3600*24*365>>(1);
    std::cout << " +365 days: " << time_point_to_string(tpsc) << std::endl;

    // add another 1 year (hoping it is valid and ignoring leap years)
    tpsc += std::chrono::duration<int,std::ratio<3600*24*365>>(1);
    std::cout << " +365 days: " << time_point_to_string(tpsc) << std::endl;
    // add one day, 23 hours, and 55 minutes
    tpsc += Days(1) + std::chrono::hours(23) + std::chrono::minutes(55);
    std::cout << "     later: " << time_point_to_string(tpsc) << std::endl;

    // process difference from epoch in minutes and days:
    auto diff = tpsc - std::chrono::system_clock::time_point();
    std::cout << "diff:"
    << std::chrono::duration_cast<std::chrono::minutes>(diff).count()
    << " minute(s)" << std::endl;
    Days days = std::chrono::duration_cast<Days>(diff);
    std::cout << "diff:" << days.count() << " day(s)" << std::endl;


    std::cout << "\nTesting predefined clocks\n";
    std::cout << "steady\tmu\t\tms\n";
    Steady_timer tim;
    F_timer_mu ft_mu;
    F_timer_ms ft_ms;
    tp = std::chrono::system_clock::now();
    while (std::chrono::system_clock::now()<tp+std::chrono::nanoseconds(54321))
        ;
    Steady_timer::Rep s_d=tim.get_duration();
    F_timer_mu::Rep f_d=ft_mu.get_duration();
    F_timer_ms::Rep fd_ms=ft_ms.get_duration();
	std::cout  << s_d << '\t' << f_d << '\t' << fd_ms << '\n';
    tp = std::chrono::system_clock::now();
    while (std::chrono::system_clock::now()<tp+std::chrono::nanoseconds(54321))
        ;
    s_d=tim.get_duration();
    f_d=ft_mu.get_duration();
    fd_ms=ft_ms.get_duration();
	std::cout  << s_d << '\t' << f_d << '\t' << fd_ms << '\n';
    ft_mu.reset();
    ft_ms.reset();
    tim.reset();
    tp = std::chrono::system_clock::now();
    while (std::chrono::system_clock::now()<tp+std::chrono::nanoseconds(54321))
        ;
    s_d=tim.get_duration();
    f_d=ft_mu.get_duration();
    fd_ms=ft_ms.get_duration();
    std::cout  << s_d << '\t' << f_d << '\t' << fd_ms << '\n';

}
