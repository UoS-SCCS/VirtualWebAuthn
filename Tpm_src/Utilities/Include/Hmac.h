/***************************************************************************
* File:        Hmac.h
* Description: Hmac functions
*
* Author:      Chris Newton
* Created:     Sunday 29 March 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once

#include <memory>
#include <openssl/hmac.h>
#include "Byte_buffer.h"

using Hmac_ctx_ptr=std::unique_ptr<HMAC_CTX,decltype(&::HMAC_CTX_free)>;

const unsigned int sha256_bytes=32;

Byte_buffer hmac_sha256(Byte_buffer const& key, Byte_buffer const& data);

Byte_buffer hmac_sha384(Byte_buffer const& key, Byte_buffer const& data);

