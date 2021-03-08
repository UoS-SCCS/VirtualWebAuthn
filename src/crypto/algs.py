"""Enum containing acceptable COSE encoded algorithms

    Enums:
        PUBLIC_KEY_ALG
"""
"""
 © Copyright 2020-2021 University of Surrey

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

"""
from enum import Enum, unique
@unique
class PUBLIC_KEY_ALG(Enum):
    """COSE Public Key algorithm values
    """
    RS512 =	-259 #	RSASSA-PKCS1-v1_5 using SHA-512 	IESG 	[RFC8812] 	No
    RS384 =	-258 #	RSASSA-PKCS1-v1_5 using SHA-384 	IESG 	[RFC8812] 	No
    RS256 =	-257 #	RSASSA-PKCS1-v1_5 using SHA-256 	IESG 	[RFC8812] 	No
    HSS_LMS = -46
    RSAES_OAEP_with_SHA_512 = -42
    RSAES_OAEP_with_SHA_256 = -41
    RSAES_OAEP_with_RFC_8017_default_parameters = -40
    PS512 = -39
    PS384 = -38
    PS256 = -37
    ES512 = -36
    ES384 = -35
    ECDH_SS_A256KW = -34
    ECDH_SS_A192KW = -33
    ECDH_SS_A128KW = -32
    ECDH_ES_A256KW = -31
    ECDH_ES_A192KW = -30
    ECDH_ES_A128KW = -29
    ECDH_SS_HKDF_512 = -28
    ECDH_SS_HKDF_256 = -27
    ECDH_ES_HKDF_512 = -26
    ECDH_ES_HKDF_256 = -25
    direct_HKDF_AES_256 = -13
    direct_HKDF_AES_128 = -12
    direct_HKDF_SHA_512 = -11
    direct_HKDF_SHA_256 = -10
    EdDSA = -8  # EdDSA   [RFC8152]  Yes
    ES256 = -7  # ECDSA w/ SHA-256   [RFC8152]  Yes
    direct = -6  # Direct use of CEK   [RFC8152]  Yes
    A256KW = -5  # AES Key Wrap w/ 256-bit key   [RFC8152]  Yes
    A192KW = -4  # AES Key Wrap w/ 192-bit key   [RFC8152]  Yes
    A128KW = -3  # AES Key Wrap w/ 128-bit key   [RFC8152]  Yes
    A128GCM = 1  # AES-GCM mode w/ 128-bit key, 128-bit tag   [RFC8152]  Yes
    A192GCM = 2  # AES-GCM mode w/ 192-bit key, 128-bit tag   [RFC8152]  Yes
    A256GCM = 3  # AES-GCM mode w/ 256-bit key, 128-bit tag   [RFC8152]  Yes
    HMAC_256_64 = 4  # HMAC w/ SHA-256 truncated to 64 bits   [RFC8152]  Yes
    HMAC_256_256 = 5  # HMAC w/ SHA-256   [RFC8152]  Yes
    HMAC_384_384 = 6  # HMAC w/ SHA-384   [RFC8152]  Yes
    HMAC_512_512 = 7  # HMAC w/ SHA-512   [RFC8152]  Yes
    # AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce   [RFC8152]  Yes
    AES_CCM_16_64_128 = 10
    # AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce   [RFC8152]  Yes
    AES_CCM_16_64_256 = 11
    # AES_CCM mode 128_bit key, 64_bit tag, 7_byte nonce   [RFC8152]  Yes
    AES_CCM_64_64_128 = 12
    # AES_CCM mode 256_bit key, 64_bit tag, 7_byte nonce   [RFC8152]  Yes
    AES_CCM_64_64_256 = 13
    AES_MAC_128_64 = 14  # AES_MAC 128_bit key, 64_bit tag 		[RFC8152] 	Yes
    AES_MAC_256_64 = 15  # AES_MAC 256_bit key, 64_bit tag 		[RFC8152] 	Yes
    # ChaCha20/Poly1305 w/ 256_bit key, 128_bit tag   [RFC8152]  Yes
    ChaCha20_Poly1305 = 24
    AES_MAC_128_128 = 25  # AES_MAC 128_bit key, 128_bit tag   [RFC8152]  Yes
    AES_MAC_256_128 = 26  # AES_MAC 256_bit key, 128_bit tag   [RFC8152]  Yes
    # AES_CCM mode 128_bit key, 128_bit tag, 13_byte nonce   [RFC8152]  Yes
    AES_CCM_16_128_128 = 30
    # AES_CCM mode 256_bit key, 128_bit tag, 13_byte nonce   [RFC8152]  Yes
    AES_CCM_16_128_256 = 31
    # AES_CCM mode 128_bit key, 128_bit tag, 7_byte nonce   [RFC8152]  Yes
    AES_CCM_64_128_128 = 32
    # AES_CCM mode 256_bit key, 128_bit tag, 7_byte nonce 		[RFC8152] 	Yes
    AES_CCM_64_128_256 = 33

