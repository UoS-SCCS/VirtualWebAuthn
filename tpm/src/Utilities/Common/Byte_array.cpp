/*******************************************************************************
* File:        Byte_array.h
* Description: Data structures used for interfacing with the Python code
*
* Author:      Chris Newton
*
* Created:     Friday 11 December 2020
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

#include <cstring>
#include "Byte_buffer.h"
#include "Byte_array.h"

void copy_byte_array(Byte_array& lhs, Byte_array const& rhs)
{
	if (&lhs!=&rhs)
	{
		release_byte_array(lhs);		
		lhs.size=rhs.size;
		lhs.data=new Byte[lhs.size];
		if (lhs.data==nullptr)
		{
			throw std::runtime_error("Unable to aloocate memory the a Byte_array");
		}
		memcpy(lhs.data,rhs.data,rhs.size);
	}
}

void release_byte_array(Byte_array& ba)
{
	if (ba.data!=nullptr)
	{
		delete [] ba.data;
		ba.data=nullptr;
	}
	ba.size=0;
}

Byte_buffer byte_array_to_bb(Byte_array const& ba)
{
    return Byte_buffer(ba.data,ba.size);
}

void bb_to_byte_array(Byte_array& ba, Byte_buffer const& bb)
{
    release_byte_array(ba);
    ba.size=static_cast<uint16_t>(bb.size());
    ba.data=new Byte[ba.size];
    if (ba.data==nullptr)
    {
		throw std::runtime_error("Unable to aloocate memory for a Byte_array");
    }
    memcpy(ba.data,bb.cdata(),ba.size);
}

std::string byte_array_to_string(Byte_array const& ba)
{
	char* char_ptr=reinterpret_cast<char*>(ba.data);
	return std::string(char_ptr,ba.size);	
}

//void string_to_byte_array(Byte_array& ba, std::string const& str)

