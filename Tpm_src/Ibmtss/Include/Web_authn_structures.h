/*****************************************************************************
* File:        Web_authn_structures.h
* Description: Data structures used for interfacing with the Python code
*
* Author:      Chris Newton
*
* Created:     Wedensday 9 December 2020
*
* (C) Copyright 2020, University of Surrey, all rights reserved.
*
*****************************************************************************/

#pragma once

#include "Byte_buffer.h"
#include "Byte_array.h"
#include "Tss_includes.h"


struct Two_byte_arrays
{
	Byte_array one;
	Byte_array two;
};


/* The key data, the handles for the parent and (when loaded) the key itself.
 * Data passed to the TPM as authorisation data cannot be larger than the size
 * of the hash being used - we will start by using SHA256. Note that
 * MAX_DIGEST_SIZE may be larger than SHA256_DIGEST_SIZE.
 * Memory for the public and private data returned when the key is created will
 * be allocated and freed in in the C++ code.
 */
struct Key_data
{
	Byte_array public_data;
	Byte_array private_data;
};

/* The public ECC key, a point on the chosen ECC curve the curve will initially
 * be NIST P_256. Note that MAX_ECC_KEY_BYTES may be larger than necessary.
*/
struct Key_ecc_point
{
	Byte_array x_coord;
	Byte_array y_coord;
};

/* The data to be signed, this cannot be larger then the size of the hash being
 * used - SHA256 in our case. Note that MAX_DIGEST_SIZE may be larger than
 * SHA256_DIGEST_SIZE.
 * 
 * Just a Byte_array
 */

/* The ECDSA signature returned from the TPM. Note the actual size may be less
 * than MAX_ECC_KEY_BYTES.
*/
struct Ecdsa_sig
{
	Byte_array sig_r;
	Byte_array sig_s;
};
