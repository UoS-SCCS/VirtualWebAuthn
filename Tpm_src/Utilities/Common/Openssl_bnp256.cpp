/******************************************************************************
* File:        Openssl_bnp256.cpp
* Description: Openssl setup for the bn_p256 EC curve
*
* Author:      Chris Newton
*
* Created:     Friday 18 May 2018
*
*
******************************************************************************/

#include <iostream>
#include <openssl/ec.h>
#include "bnp256_param.h"
#include "Number_conversions.h"

EC_GROUP *get_ec_group_bnp256()
{
    int ok = 0;
    EC_GROUP *curve = nullptr;
    EC_POINT *generator = nullptr;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *tmp_1 = nullptr;
    BIGNUM *tmp_2 = nullptr;
    BIGNUM *tmp_3 = nullptr;

    if ((tmp_1 = bb2bn(bnp256_p, nullptr)) == nullptr) {
        goto err;   // NOLINT
}
    if ((tmp_2 = bb2bn(bnp256_a, nullptr)) == nullptr) {
        goto err;   // NOLINT
}
    if ((tmp_3 = bb2bn(bnp256_b, nullptr)) == nullptr) {
        goto err;   // NOLINT
}
    if ((curve = EC_GROUP_new_curve_GFp(tmp_1, tmp_2, tmp_3, nullptr)) == nullptr) {
        goto err;   // NOLINT
}

    //	std::cout << "p: " << BN_bn2hex(tmp_1) << '\n';
    //	std::cout << "a: " << BN_bn2hex(tmp_2) << '\n';
    //	std::cout << "b: " << BN_bn2hex(tmp_3) << '\n';

    /* build generator */
    generator = EC_POINT_new(curve);
    if (generator == nullptr) {
        goto err;   // NOLINT
}
    if ((tmp_1 = bb2bn(bnp256_gX, tmp_1)) == nullptr) {
        goto err;   // NOLINT
}
    if ((tmp_2 = bb2bn(bnp256_gY, tmp_2)) == nullptr) {
        goto err;   // NOLINT
}
    if (1 != EC_POINT_set_affine_coordinates_GFp(curve, generator, tmp_1, tmp_2, ctx)) {
        goto err;   // NOLINT
}

    //	std::cout << "gX: " << BN_bn2hex(tmp_1) << '\n';
    //	std::cout << "gY: " << BN_bn2hex(tmp_2) << '\n';

    if ((tmp_1 = bb2bn(bnp256_order, tmp_1)) == nullptr) {
        goto err;   // NOLINT
}
    BN_one(tmp_2);
    if (1 != EC_GROUP_set_generator(curve, generator, tmp_1, tmp_2)) {
        goto err;   // NOLINT
}

    //	std::cout << "order: " << BN_bn2hex(tmp_1) << '\n';

    ok = 1;
//	std::cout << "Curve generation succeeded\n";
err:
    if (tmp_1==nullptr) {
        BN_free(tmp_1);
}
    if (tmp_2==nullptr) {
        BN_free(tmp_2);
}
    if (tmp_3==nullptr) {
        BN_free(tmp_3);
}
    if (generator==nullptr) {
        EC_POINT_free(generator);
}
    if (ctx==nullptr) {
        BN_CTX_free(ctx);
}
    if (ok == 0) {
        EC_GROUP_free(curve);
        curve = nullptr;
    }
    //	std::cout << "Returning to caller after generating curve\n";
    return (curve);
}
