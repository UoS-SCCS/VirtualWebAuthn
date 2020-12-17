/******************************************************************************
* File:        bnp256_param.h
* Description: Parameters for the bn_p256 EC curve
*
* Author:      Chris Newton
*
* Created:     Friday 18 May 2018
*
*
******************************************************************************/

#pragma once

#include "Byte_buffer.h"

/* Extracted from Mechanism 4:
t=
256
p = TPM(n) = order
FFFFFFFF FFFCF0CD 46E5F25E EE71A49E 0CDC65FB 1299921A F62D536C D10B500D

q = TPM(p) for F_p
FFFFFFFF FFFCF0CD 46E5F25E EE71A49F 0CDC65FB 12980A82 D3292DDB AED33013

b =
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000003

beta =
FFFFFFFF FFFCF0CD 46E5F25E EE71A49F 0CDC65FB 12980A82 D3292DDB AED33012

P1 = TPM(gX,gY) = generator
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000002

*/

const size_t component_size=32;

const Hex_string hex_bnp256_p("FFFFFFFFFFFCF0CD46E5F25EEE71A49F0CDC65FB12980A82D3292DDBAED33013");
const Byte_buffer bnp256_p(hex_bnp256_p);

const Byte_buffer bnp256_a{0x00};

const Byte_buffer bnp256_b{0x03};

const Byte_buffer bnp256_gX{0x01};

const Byte_buffer bnp256_gY{0x02};

const Hex_string hex_bnp256_order("FFFFFFFFFFFCF0CD46E5F25EEE71A49E0CDC65FB1299921AF62D536CD10B500D");
const Byte_buffer bnp256_order(hex_bnp256_order);

//static unsigned char ec_cofactor_256[] = {
//	0x01
//	};
	
/* Test example for curve bn_p256 curve from ISO Mechanism 4:

f =
05E8D2E3 F942A58F 652CE4B7 2836BB01 23AF440F E74004CC 0E0F37F5 59BAC367
Q2 =
2F858C21 7C1F2818 F1912A72 20852462 8AE6FC53 49A97D82 D6ACB646 AD3A4284
B1A886C3 3E5443AF 1499EF32 F0CB5186 B7F25E52 FBA05426 CFD590B1 974143DF

*/

const Hex_string hex_iso_test_sk("05E8D2E3F942A58F652CE4B72836BB0123AF440FE74004CC0E0F37F559BAC367");
const Byte_buffer iso_test_sk(hex_iso_test_sk);

const Hex_string hex_iso_test_pk_x("2F858C217C1F2818F1912A72208524628AE6FC5349A97D82D6ACB646AD3A4284");
const Byte_buffer iso_test_pk_x(hex_iso_test_pk_x);

const Hex_string hex_iso_test_pk_y("B1A886C33E5443AF1499EF32F0CB5186B7F25E52FBA05426CFD590B1974143DF");
const Byte_buffer iso_test_pk_y(hex_iso_test_pk_y);

