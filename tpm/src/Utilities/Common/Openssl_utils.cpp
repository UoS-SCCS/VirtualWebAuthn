/***************************************************************************
* File:        Openssl_utils.cpp
* Description: Utility functions for Openssl
*
* Author:      Chris Newton
* Created:     Monday 7 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

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
