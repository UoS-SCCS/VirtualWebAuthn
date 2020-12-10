/***************************************************************************
* File:        Openssl_bn_utils.cpp
* Description: Utility functions for Openssl BIGNUMs
*
* Author:      Chris Newton
* Created:     Wednesday 20 June 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/
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

Byte_buffer bb_mod(Byte_buffer const& num,Byte_buffer const& modulus)
{
	Bn_ctx_ptr ctx=new_bn_ctx();
	Bn_ptr mod_bn=new_bn();
    BN_bin2bn(&modulus[0],modulus.size(),mod_bn.get());

	Bn_ptr n_bn=new_bn();
    BN_bin2bn(&num[0],num.size(),n_bn.get());

	Byte_buffer result;
	Bn_ptr rem_bn=new_bn();
    if (1!=BN_nnmod(rem_bn.get(),n_bn.get(),mod_bn.get(),ctx.get()))
    {
        throw(Openssl_error("Mod calculation failed"));;
    }

	return bn2bb(rem_bn.get());
}

Byte_buffer bb_add(Byte_buffer const& a,Byte_buffer const& b)
{
	Bn_ptr a_bn=new_bn();
    BN_bin2bn(&a[0],a.size(),a_bn.get());

	Bn_ptr b_bn=new_bn();
    BN_bin2bn(&b[0],b.size(),b_bn.get());

	Byte_buffer result;
	Bn_ptr res_bn=new_bn();
    if (1!=BN_add(res_bn.get(),a_bn.get(),b_bn.get()))
    {
        throw(Openssl_error("Addition failed"));
    }

	return bn2bb(res_bn.get());
}

Byte_buffer bb_mod_add(Byte_buffer const& a,Byte_buffer const& b,Byte_buffer const& n)
{
    Bn_ctx_ptr ctx=new_bn_ctx();
	Bn_ptr a_bn=new_bn();
    BN_bin2bn(&a[0],a.size(),a_bn.get());

	Bn_ptr b_bn=new_bn();
    BN_bin2bn(&b[0],b.size(),b_bn.get());

	Bn_ptr n_bn=new_bn();
    BN_bin2bn(&n[0],n.size(),n_bn.get());

	Byte_buffer result;
	Bn_ptr res_bn=new_bn();
    if (1!=BN_mod_add(res_bn.get(),a_bn.get(),b_bn.get(),n_bn.get(),ctx.get()))
    {
        throw(Openssl_error("Modular_addition failed"));
    }

	return bn2bb(res_bn.get());
}

Byte_buffer bb_sub(Byte_buffer const& a,Byte_buffer const& b)
{
	Bn_ptr a_bn=new_bn();
    BN_bin2bn(&a[0],a.size(),a_bn.get());

	Bn_ptr b_bn=new_bn();
    BN_bin2bn(&b[0],b.size(),b_bn.get());

	Byte_buffer result;
	Bn_ptr res_bn=new_bn();
    if (1!=BN_sub(res_bn.get(),a_bn.get(),b_bn.get()))
    {
        throw(Openssl_error("Addition failed"));
    }

	return bn2bb(res_bn.get());
}

Byte_buffer bb_mod_sub(Byte_buffer const& a,Byte_buffer const& b,Byte_buffer const& n)
{
    Bn_ctx_ptr ctx=new_bn_ctx();
	Bn_ptr a_bn=new_bn();
    BN_bin2bn(&a[0],a.size(),a_bn.get());

	Bn_ptr b_bn=new_bn();
    BN_bin2bn(&b[0],b.size(),b_bn.get());

	Bn_ptr n_bn=new_bn();
    BN_bin2bn(&n[0],n.size(),n_bn.get());

	Byte_buffer result;
	Bn_ptr res_bn=new_bn();
    if (1!=BN_mod_sub(res_bn.get(),a_bn.get(),b_bn.get(),n_bn.get(),ctx.get()))
    {
        throw(Openssl_error("Modular_addition failed"));
    }

	return bn2bb(res_bn.get());
}

Byte_buffer bb_mul(Byte_buffer const& a,Byte_buffer const& b)
{
	Bn_ctx_ptr ctx=new_bn_ctx();
	Bn_ptr a_bn=new_bn();
    BN_bin2bn(&a[0],a.size(),a_bn.get());

	Bn_ptr b_bn=new_bn();
    BN_bin2bn(&b[0],b.size(),b_bn.get());

	Byte_buffer result;
	Bn_ptr res_bn=new_bn();
    if (1!=BN_mul(res_bn.get(),a_bn.get(),b_bn.get(),ctx.get()))
    {
        throw(Openssl_error("Multiplication failed"));
    }

	return bn2bb(res_bn.get());
}

Byte_buffer bb_mod_mul(Byte_buffer const& a,Byte_buffer const& b,Byte_buffer const& n)
{
	Bn_ctx_ptr ctx=new_bn_ctx();
	Bn_ptr a_bn=new_bn();
    BN_bin2bn(&a[0],a.size(),a_bn.get());

	Bn_ptr b_bn=new_bn();
    BN_bin2bn(&b[0],b.size(),b_bn.get());

	Bn_ptr n_bn=new_bn();
    BN_bin2bn(&n[0],n.size(),n_bn.get());

	Byte_buffer result;
	Bn_ptr res_bn=new_bn();
    if (1!=BN_mod_mul(res_bn.get(),a_bn.get(),b_bn.get(),n_bn.get(),ctx.get()))
    {
        throw(Openssl_error("Modular multiplication failed"));
    }

	return bn2bb(res_bn.get());
}

Byte_buffer bb_signature_calc(Byte_buffer const& a,Byte_buffer const& b,Byte_buffer const&c,Byte_buffer const& modulus)
{
	Bn_ctx_ptr ctx=new_bn_ctx();
	Bn_ptr bn_n=new_bn();
    BN_bin2bn(&modulus[0],modulus.size(),bn_n.get());

	Bn_ptr bn_a=new_bn();
    BN_bin2bn(&a[0],a.size(),bn_a.get());

	Bn_ptr bn_b=new_bn();
    BN_bin2bn(&b[0],b.size(),bn_b.get());

	Bn_ptr bn_tmp=new_bn();
    BN_bin2bn(&c[0],c.size(),bn_tmp.get());

	Byte_buffer result;
	if (1!=BN_mul(bn_tmp.get(),bn_b.get(),bn_tmp.get(),ctx.get()))
    {
        throw(Openssl_error("Multiplication failed (bxc)"));
    }

	if (1!=BN_mod_add(bn_tmp.get(),bn_a.get(),bn_tmp.get(),bn_n.get(),ctx.get()))
    {
        throw(Openssl_error("Addition failed (a+bxc)"));
    }

	return bn2bb(bn_tmp.get());

}