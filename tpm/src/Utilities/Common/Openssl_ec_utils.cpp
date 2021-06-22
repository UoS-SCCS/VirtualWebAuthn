/***************************************************************************
* File:        Openssl_ec_utils.cpp
* Description: Utility functions for Openssl EC
*
* Author:      Chris Newton
* Created:     Wednesday 20 June 2018
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
*
****************************************************************************/

#include <exception>
#include "Openssl_utils.h"
#include "Number_conversions.h"
#include "Io_utils.h"
#include "Openssl_ec_utils.h"
#include "Openssl_bn_utils.h"

Ec_group_ptr new_ec_group(std::string const &curve_name)
{
    std::string cn_lower=str_tolower(curve_name);
    EC_GROUP *ecgrp = nullptr;
    if (cn_lower == "bnp256") {
        ecgrp = get_ec_group_bnp256();
    } else {
        int nid = OBJ_txt2nid(cn_lower.c_str());
        ecgrp = EC_GROUP_new_by_curve_name(nid);
    }
    if (ecgrp == nullptr) {
        throw(Openssl_error("Error generating the EC_GROUP"));
    }

    return Ec_group_ptr(ecgrp, ::EC_GROUP_free);
}

Ec_key_ptr new_ec_key()
{
    return Ec_key_ptr(EC_KEY_new(), ::EC_KEY_free);
}

Ec_point_ptr new_ec_point(Ec_group_ptr const &ecgrp)
{
    return Ec_point_ptr(EC_POINT_new(ecgrp.get()), ::EC_POINT_free);
}

G1_point point2bb(Ec_group_ptr const &ecgrp, Ec_point_ptr const &point)
{
    return point2bb0(ecgrp, point.get());
}

G1_point point2bb0(Ec_group_ptr const &ecgrp, Ec_point_ptr0 point)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Bn_ptr x_bn = new_bn();
    Bn_ptr y_bn = new_bn();

    if (1 != EC_POINT_get_affine_coordinates_GFp(ecgrp.get(), point, x_bn.get(), y_bn.get(), ctx.get())) {
        throw(Openssl_error("point2bb0 failed"));
    }

    return std::make_pair(bn2bb(x_bn.get()), bn2bb(y_bn.get()));
}

// Pass in the point so we don't worry about cleaning up
void bb2point(Ec_group_ptr const &ecgrp, G1_point const &pt_bb, Ec_point_ptr &pt)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Bn_ptr x_bn = new_bn();
    Bn_ptr y_bn = new_bn();
    bin2bn(pt_bb.first.cdata(), pt_bb.first.size(), x_bn.get());
//    bb2bn(pt_bb.first,x_bn.get());
    bin2bn(pt_bb.second.cdata(), pt_bb.second.size(), y_bn.get());
//    bb2bn(pt_bb.second,x_bn.get());

    if (1 != EC_POINT_set_affine_coordinates_GFp(ecgrp.get(), pt.get(), x_bn.get(), y_bn.get(), ctx.get())) {
        throw(Openssl_error("bb2point failed"));
    }
}

bool point_is_on_curve(Ec_group_ptr const &ecgrp, G1_point const &pt_bb)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Ec_point_ptr pt = new_ec_point(ecgrp);

    bool result = true;
    try {
        bb2point(ecgrp, pt_bb, pt);
    } catch (Openssl_error const &e) {
        result = false;
    }

    return result;
}

bool point_is_at_infinity(Ec_group_ptr const &ecgrp, G1_point const &pt_bb)
{
    Ec_point_ptr pt = new_ec_point(ecgrp);

    bb2point(ecgrp, pt_bb, pt);
    bool result = true;
    if (1 != EC_POINT_is_at_infinity(ecgrp.get(), pt.get())) {
        result = false;
    }

    return result;
}

G1_point ec_point_add(
  Ec_group_ptr const &ecgrp,
  G1_point const &pt_a_bb,
  G1_point const &pt_b_bb)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Ec_point_ptr pt_a = new_ec_point(ecgrp);
    bb2point(ecgrp, pt_a_bb, pt_a);
    Ec_point_ptr pt_b = new_ec_point(ecgrp);
    bb2point(ecgrp, pt_b_bb, pt_b);
    Ec_point_ptr pt_r = new_ec_point(ecgrp);

    G1_point result;

    if (1 != EC_POINT_add(ecgrp.get(), pt_r.get(), pt_a.get(), pt_b.get(), ctx.get())) {
        std::cout << "ec_point_add failed\n";
        handle_openssl_error();
    } else {
        result = point2bb(ecgrp, pt_r);
    }

    return result;
}

G1_point ec_generator_mul(
  Ec_group_ptr const &ecgrp,
  Byte_buffer const &multiplier)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Bn_ptr m_bn = new_bn();
    bin2bn(&multiplier[0], multiplier.size(), m_bn.get());
    Ec_point_ptr res = new_ec_point(ecgrp);
    G1_point result;

    if (1 != EC_POINT_mul(ecgrp.get(), res.get(), m_bn.get(), nullptr, nullptr, ctx.get())) {
        std::cout << "ec_generator_mul failed\n";
        handle_openssl_error();
    } else {
        result = point2bb(ecgrp, res);
    }

    return result;
}

G1_point ec_point_mul(
  Ec_group_ptr const &ecgrp,
  Byte_buffer const &multiplier,
  G1_point const &pt_bb)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Bn_ptr m_bn = new_bn();
    bin2bn(&multiplier[0], multiplier.size(), m_bn.get());
    Ec_point_ptr pt = new_ec_point(ecgrp);
    bb2point(ecgrp, pt_bb, pt);
    Ec_point_ptr res = new_ec_point(ecgrp);

    G1_point result;

    if (1 != EC_POINT_mul(ecgrp.get(), res.get(), nullptr, pt.get(), m_bn.get(), ctx.get())) {
        std::cout << "ec_point_mul failed\n";
        handle_openssl_error();
    } else {
        result = point2bb(ecgrp, res);
    }

    return result;
}


G1_point ec_point_invert(
  Ec_group_ptr const &ecgrp,
  G1_point const &pt_bb)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Ec_point_ptr pt = new_ec_point(ecgrp);
    bb2point(ecgrp, pt_bb, pt);

    G1_point result;

    if (1 != EC_POINT_invert(ecgrp.get(), pt.get(), ctx.get())) {
        std::cout << "ec_point_invert failed\n";
        handle_openssl_error();
    } else {
        result = point2bb(ecgrp, pt);
    }

    return result;
}

Ec_key_pair_bb get_new_key_pair(Ec_group_ptr const &ecgrp)
{
    Bn_ctx_ptr ctx = new_bn_ctx();
    Ec_key_pair_bb result;
    Ec_key_ptr new_key = new_ec_key();
    if (1 != EC_KEY_set_group(new_key.get(), ecgrp.get())) {
        std::cout << "Associating a key with the curve failed\n";
    } else if (EC_KEY_generate_key(new_key.get()) <= 0) {
        std::cout << "Failed to generate a new test key\n";
    } else {
        //	std::cout << "New key generated\n";
        Byte_buffer new_sk_bb = bn2bb(EC_KEY_get0_private_key(new_key.get()));

        EC_POINT const *new_pk_pt = EC_KEY_get0_public_key(new_key.get());
        G1_point pt_bb = point2bb0(ecgrp, new_pk_pt);

        result.first = new_sk_bb;
        result.second = pt_bb;
    }

    return result;
}

bool verify_ecdsa_signature(
std::string curve_name,
G1_point const& ecdsa_public_key,
Byte_buffer const& digest_to_sign,
Byte_buffer const& sigR,
Byte_buffer const& sigS
)
{
	Bn_ctx_ptr ctx=new_bn_ctx();
	Ec_group_ptr ecgrp=new_ec_group(curve_name);

	if (1!=EC_GROUP_check(ecgrp.get(),ctx.get())) {
		throw(Openssl_error("EC_GROUP_check failed"));
	}

	if (!point_is_on_curve(ecgrp,ecdsa_public_key)) 	{
		throw(Openssl_error("The ECDSA public key is not on the curve"));
	}

	Ec_key_ptr ec_key=new_ec_key();
	EC_KEY_set_group(ec_key.get(),ecgrp.get());
	Ec_point_ptr pub_key=new_ec_point(ecgrp);
	bb2point(ecgrp,ecdsa_public_key,pub_key);

	if (1!=EC_KEY_set_public_key(ec_key.get(), pub_key.get())) {
	// could also use: EC_KEY_set_public_key_affine_coordinates 
		throw(Openssl_error("Failed to load public key (OpenSSL)"));
	}

	BIGNUM* sig_r=BN_new(); // Freed when freeing ECDSA_SIG, so don't use unique pointer
	bin2bn(sigR.cdata(),sigR.size(),sig_r);
	BIGNUM* sig_s=BN_new();  // Freed when freeing ECDSA_SIG, so don't use unique pointer
	bin2bn(sigS.cdata(),sigS.size(),sig_s);
	ECDSA_SIG* ossl_sig=ECDSA_SIG_new();
	ECDSA_SIG_set0(ossl_sig,sig_r,sig_s); 

	int ret=ECDSA_do_verify(digest_to_sign.cdata(),static_cast<int>(digest_to_sign.size()),ossl_sig,ec_key.get());
	if (ret<0) {
		throw(Openssl_error("ECDSA_do_verify failed"));
	}
	bool verifiedOK=(ret==1);

	if (ossl_sig) {
		ECDSA_SIG_free(ossl_sig);
	}

	return verifiedOK;	
}

