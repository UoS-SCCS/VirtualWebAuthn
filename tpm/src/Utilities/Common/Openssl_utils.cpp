/*******************************************************************************
* File:        Openssl_utils.cpp
* Description: Utility functions for Openssl
*
* Author:      Chris Newton
* Created:     Monday 7 May 2018
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

#include <cstdio>
#include "Openssl_utils.h"

void init_openssl()
{
    OpenSSL_add_all_algorithms(); // NOLINT
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}

void cleanup_openssl()
{
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    EVP_cleanup();
}

void handle_openssl_error()
{
    ERR_print_errors_fp(stderr);
}

auto fp_deleter=[](FILE* fp) {
    fclose(fp); // NOLINT
};

std::string get_openssl_error()
{
    using file_ptr=std::unique_ptr<FILE,decltype(fp_deleter)>;
//    FILE *stream;
    char *buf = nullptr;
    size_t len = 0;
    // buf allocated in C call, we must free it
    file_ptr stream(open_memstream(&buf, &len),fp_deleter);
    if (stream.get() == nullptr) {
        return std::string("Unable to open a stream to retrieve the error");
    }

    ERR_print_errors_fp(stream.get());
    fflush(stream.get());   // NOLINT

    std::string ossl_err(buf);
    free(buf); // NOLINT

    return ossl_err;
}
