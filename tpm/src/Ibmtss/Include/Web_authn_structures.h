/*******************************************************************************
* File:        Web_authn_structures.h
* Description: Data structures used for interfacing with the Python code
*
* Author:      Chris Newton
*
* Created:     Wedensday 9 December 2020
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

#include "Byte_buffer.h"
#include "Byte_array.h"
#include "Tss_includes.h"

/* The key data. Memory for the public and private data returned when the key is
 * created will be allocated and freed in in the C++ code.
 */
struct Key_data
{
    Byte_array public_data;
    Byte_array private_data;
};

/* The public ECC key, a point on the chosen ECC curve the curve will initially
 * be NIST P_256. Memory for the x_coord and y_coord will be allocated and
 * freed in the C++ code
*/
struct Key_ecc_point
{
    Byte_array x_coord;
    Byte_array y_coord;
};

/* The key data and the public key (ECC point). Memory needed will be allocated
 * and freed in the C++ code 
*/
struct Relying_party_key
{
    Key_data key_blob;
    Key_ecc_point key_point;
};

/* The data to be signed, this cannot be larger then the size of the hash being
 * used - SHA256 in our case. Note that MAX_DIGEST_SIZE may be larger than
 * SHA256_DIGEST_SIZE.
 * 
 * Just a Byte_array, allocated and freed by the caller
 */

/* The ECDSA signature returned from the TPM. Note the actual size may be less
 * than MAX_ECC_KEY_BYTES. Memory needed will be allocated and freed in the C++
 * code 
*/
struct Ecdsa_sig
{
    Byte_array sig_r;
    Byte_array sig_s;
};
