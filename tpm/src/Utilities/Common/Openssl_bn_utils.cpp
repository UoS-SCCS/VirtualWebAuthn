/*******************************************************************************
* File:        Openssl_bn_utils.cpp
* Description: Utility functions for Openssl BIGNUMs
*
* Author:      Chris Newton
* Created:     Wednesday 20 June 2018
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
#include "Openssl_utils.h"
#include "Number_conversions.h"
#include "Openssl_bn_utils.h"

Bn_ctx_ptr new_bn_ctx()
{
    return Bn_ctx_ptr(BN_CTX_new(), ::BN_CTX_free);
}

Bn_ptr new_bn()
{
    return Bn_ptr(BN_new(), ::BN_free);
}

Byte_buffer bb_mod(Byte_buffer const &num, Byte_buffer const &modulus)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Bn_ptr mod_bn = new_bn();
    BN_bin2bn(modulus.cdata(), static_cast<int>(modulus.size()), mod_bn.get());
//    bb2bn(modulus,mod_bn.get());

    Bn_ptr n_bn = new_bn();
    BN_bin2bn(num.cdata(), static_cast<int>(num.size()), n_bn.get());
//    bb2bn(num,n_bn.get());

    Byte_buffer result;
    Bn_ptr rem_bn = new_bn();
    if (1 != BN_nnmod(rem_bn.get(), n_bn.get(), mod_bn.get(), ctx.get())) {
        throw(Openssl_error("Mod calculation failed"));
        ;
    }

    return bn2bb(rem_bn.get());
}

Byte_buffer bb_add(Byte_buffer const &a, Byte_buffer const &b)
{
    Bn_ptr a_bn = new_bn();
    BN_bin2bn(a.cdata(), static_cast<int>(a.size()), a_bn.get());
//    bb2bn(a,a_bn.get());

    Bn_ptr b_bn = new_bn();
    BN_bin2bn(b.cdata(), static_cast<int>(b.size()), b_bn.get());
//    bb2bn(b,b_bn.get());

    Byte_buffer result;
    Bn_ptr res_bn = new_bn();
    if (1 != BN_add(res_bn.get(), a_bn.get(), b_bn.get())) {
        throw(Openssl_error("Addition failed"));
    }

    return bn2bb(res_bn.get());
}

Byte_buffer bb_mod_add(Byte_buffer const &a, Byte_buffer const &b, Byte_buffer const &n)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Bn_ptr a_bn = new_bn();
    BN_bin2bn(a.cdata(), static_cast<int>(a.size()), a_bn.get());
//    bb2bn(a,a_bn.get());

    Bn_ptr b_bn = new_bn();
    BN_bin2bn(b.cdata(), static_cast<int>(b.size()), b_bn.get());
//    bb2bn(b,b_bn.get());

    Bn_ptr n_bn = new_bn();
    BN_bin2bn(n.cdata(), static_cast<int>(n.size()), n_bn.get());
//    bb2bn(n,n_bn.get());

    Byte_buffer result;
    Bn_ptr res_bn = new_bn();
    if (1 != BN_mod_add(res_bn.get(), a_bn.get(), b_bn.get(), n_bn.get(), ctx.get())) {
        throw(Openssl_error("Modular_addition failed"));
    }

    return bn2bb(res_bn.get());
}

Byte_buffer bb_sub(Byte_buffer const &a, Byte_buffer const &b)
{
    Bn_ptr a_bn = new_bn();
    BN_bin2bn(a.cdata(), static_cast<int>(a.size()), a_bn.get());
//    bb2bn(a,a_bn.get());

    Bn_ptr b_bn = new_bn();
    BN_bin2bn(b.cdata(), static_cast<int>(b.size()), b_bn.get());
//    bb2bn(b,b_bn.get());

    Byte_buffer result;
    Bn_ptr res_bn = new_bn();
    if (1 != BN_sub(res_bn.get(), a_bn.get(), b_bn.get())) {
        throw(Openssl_error("Addition failed"));
    }

    return bn2bb(res_bn.get());
}

Byte_buffer bb_mod_sub(Byte_buffer const &a, Byte_buffer const &b, Byte_buffer const &n)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Bn_ptr a_bn = new_bn();
    BN_bin2bn(a.cdata(), static_cast<int>(a.size()), a_bn.get());
//    bb2bn(a,a_bn.get());

    Bn_ptr b_bn = new_bn();
    BN_bin2bn(b.cdata(), static_cast<int>(b.size()), b_bn.get());
//    bb2bn(b,b_bn.get());

    Bn_ptr n_bn = new_bn();
    BN_bin2bn(n.cdata(), static_cast<int>(n.size()), n_bn.get());
//    bb2bn(n,n_bn.get());

    Byte_buffer result;
    Bn_ptr res_bn = new_bn();
    if (1 != BN_mod_sub(res_bn.get(), a_bn.get(), b_bn.get(), n_bn.get(), ctx.get())) {
        throw(Openssl_error("Modular_addition failed"));
    }

    return bn2bb(res_bn.get());
}

Byte_buffer bb_mul(Byte_buffer const &a, Byte_buffer const &b)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Bn_ptr a_bn = new_bn();
    BN_bin2bn(a.cdata(), static_cast<int>(a.size()), a_bn.get());
//    bb2bn(a,a_bn.get());

    Bn_ptr b_bn = new_bn();
    BN_bin2bn(b.cdata(), static_cast<int>(b.size()), b_bn.get());
//    bb2bn(b,b_bn.get());

    Byte_buffer result;
    Bn_ptr res_bn = new_bn();
    if (1 != BN_mul(res_bn.get(), a_bn.get(), b_bn.get(), ctx.get())) {
        throw(Openssl_error("Multiplication failed"));
    }

    return bn2bb(res_bn.get());
}

Byte_buffer bb_mod_mul(Byte_buffer const &a, Byte_buffer const &b, Byte_buffer const &n)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Bn_ptr a_bn = new_bn();
    BN_bin2bn(a.cdata(), static_cast<int>(a.size()), a_bn.get());
//    bb2bn(a,a_bn.get());

    Bn_ptr b_bn = new_bn();
    BN_bin2bn(b.cdata(), static_cast<int>(b.size()), b_bn.get());
//    bb2bn(b,b_bn.get());

    Bn_ptr n_bn = new_bn();
    BN_bin2bn(n.cdata(), static_cast<int>(n.size()), n_bn.get());
//    bb2bn(n,n_bn.get());

    Byte_buffer result;
    Bn_ptr res_bn = new_bn();
    if (1 != BN_mod_mul(res_bn.get(), a_bn.get(), b_bn.get(), n_bn.get(), ctx.get())) {
        throw(Openssl_error("Modular multiplication failed"));
    }

    return bn2bb(res_bn.get());
}

Byte_buffer bb_signature_calc(Byte_buffer const &a, Byte_buffer const &b, Byte_buffer const &c, Byte_buffer const &modulus)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Bn_ptr bn_n = new_bn();
    BN_bin2bn(modulus.cdata(), static_cast<int>(modulus.size()), bn_n.get());
//    bb2bn(modulus,bn_n.get());

    Bn_ptr bn_a = new_bn();
    BN_bin2bn(a.cdata(), static_cast<int>(a.size()), bn_a.get());
//    bb2bn(a,bn_a.get());

    Bn_ptr bn_b = new_bn();
    BN_bin2bn(b.cdata(), static_cast<int>(b.size()), bn_b.get());
//    bb2bn(b,bn_b.get());

    Bn_ptr bn_tmp = new_bn();
    BN_bin2bn(c.cdata(), static_cast<int>(c.size()), bn_tmp.get());
//    bb2bn(c,bn_tmp.get());

    Byte_buffer result;
    if (1 != BN_mul(bn_tmp.get(), bn_b.get(), bn_tmp.get(), ctx.get())) {
        throw(Openssl_error("Multiplication failed (bxc)"));
    }

    if (1 != BN_mod_add(bn_tmp.get(), bn_a.get(), bn_tmp.get(), bn_n.get(), ctx.get())) {
        throw(Openssl_error("Addition failed (a+bxc)"));
    }

    return bn2bb(bn_tmp.get());
}
