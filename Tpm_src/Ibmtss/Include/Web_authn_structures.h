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
#include "Tss_includes.h"

/* The key data, the handles for the parent and (when loaded) the key itself.
 * Data passed to the TPM as authorisation data cannot be larger than the size
 * of the hash being used - we will start by using SHA256. Note that
 * MAX_DIGEST_SIZE may be larger than SHA256_DIGEST_SIZE.
 * Memory for the public and private data returned when the key is created will
 * be allocated and freed in in the C++ code.
 */
struct Key_data
{
TPM_HANDLE parent;
uint16_t password_size;
Byte password[MAX_DIGEST_SIZE];
uint16_t public_data_size;
Byte* public_data;
uint16_t private_data_size;
Byte* private_data;
TPM_HANDLE handle;
};

/* The public ECC key, a point on the chosen ECC curve the curve will initially
 * be NIST P_256. Note that MAX_ECC_KEY_BYTES may be larger than necessary.
*/
struct Key_ecc_point
{
uint16_t x_size;
Byte x_coord[MAX_ECC_KEY_BYTES];
uint16_t y_size;
Byte y_coord[MAX_ECC_KEY_BYTES];
};

/* The data to be signed, this cannot be larger then the size of the hash being
 * used - SHA256 in our case. Note that MAX_DIGEST_SIZE may be larger than
 * SHA256_DIGEST_SIZE.
 */
struct Signing_data
{
uint16_t data_size;
Byte signing_data[MAX_DIGEST_SIZE];
};

/* The ECDSA signature returned from the TPM. Note the actual size may be less
 * than MAX_ECC_KEY_BYTES.
*/
struct Ecdsa_sig
{
uint16_t r_size;
Byte sig_r[MAX_ECC_KEY_BYTES];
uint16_t s_size;
Byte sig_s[MAX_ECC_KEY_BYTES];
};
