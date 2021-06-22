/***************************************************************************
* File:        Tpm_error.cpp
* Description: Error reporting for TSS
*
* Author:      Chris Newton
*
* Created:     Sunday 20 May 2018
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
*
****************************************************************************/

#include <iostream>
#include <sstream>
#include <string>
#include <cstring>
#include "Tss_includes.h"

std::string get_tpm_error(TSS_RC rc)
{
	std::ostringstream os;
    const char *msg;
	const char *submsg;
	const char *num;
	
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	os << msg << ", " << submsg << ", " << num;

	return os.str();
}


void report_tpm_error(TSS_RC rc, std::string const& comment)
{
	std::cout << comment << ". Returned: " << rc  << '\n';
	std::cout << get_tpm_error(rc) << '\n';
}

