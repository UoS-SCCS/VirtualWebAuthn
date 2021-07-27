/*******************************************************************************
* File:        Hmac_sha256.cpp
* Description: Code to generate the HMAC using SHA256
*
*
* Author:      Chris Newton
* Created:     Saturday 10 March 2018
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

#include <openssl/hmac.h>
#include "Byte_buffer.h"
#include "Hmac.h"

Hmac_ctx_ptr new_hmac_ctx()
{
    return Hmac_ctx_ptr(HMAC_CTX_new(), ::HMAC_CTX_free);
}

Byte_buffer hmac_sha256(Byte_buffer const &key, Byte_buffer const &data)
{
    unsigned int len = sha256_bytes;
    Byte_buffer result(len, 0);

    Hmac_ctx_ptr ctx = new_hmac_ctx();
    HMAC_CTX_reset(ctx.get());

    // Using sha256 hash engine here.
    HMAC_Init_ex(ctx.get(), &key[0], static_cast<int>(key.size()), EVP_sha256(), nullptr);
    HMAC_Update(ctx.get(), &data[0], data.size());
    HMAC_Final(ctx.get(), &result[0], &len);

    return result;
}

Byte_buffer hmac_sha384(Byte_buffer const &key, Byte_buffer const &data)
{
    unsigned int len = sha384_bytes;
    Byte_buffer result(len, 0);

    Hmac_ctx_ptr ctx = new_hmac_ctx();
    HMAC_CTX_reset(ctx.get());

    // Using sha256 hash engine here.
    HMAC_Init_ex(ctx.get(), &key[0], static_cast<int>(key.size()), EVP_sha256(), nullptr);
    HMAC_Update(ctx.get(), &data[0], data.size());
    HMAC_Final(ctx.get(), &result[0], &len);

    return result;
}

