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

EC_GROUP *get_ec_group_bnp256(void)
{
	int ok=0;
	EC_GROUP *curve = NULL;
	EC_POINT *generator = NULL;
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM   *tmp_1 = NULL, *tmp_2 = NULL, *tmp_3 = NULL;

	if ((tmp_1 = BN_bin2bn(&bnp256_p[0], bnp256_p.size(), NULL)) == NULL)
		goto err;
	if ((tmp_2 = BN_bin2bn(&bnp256_a[0], bnp256_a.size(), NULL)) == NULL)
		goto err;
	if ((tmp_3 = BN_bin2bn(&bnp256_b[0], bnp256_b.size(), NULL)) == NULL)
		goto err;
	if ((curve = EC_GROUP_new_curve_GFp(tmp_1, tmp_2, tmp_3, NULL)) == NULL)
		goto err;

//	std::cout << "p: " << BN_bn2hex(tmp_1) << '\n';
//	std::cout << "a: " << BN_bn2hex(tmp_2) << '\n';
//	std::cout << "b: " << BN_bn2hex(tmp_3) << '\n';

	/* build generator */
	generator = EC_POINT_new(curve);
	if (generator == NULL)
		goto err;
	if ((tmp_1 = BN_bin2bn(&bnp256_gX[0], bnp256_gX.size(), tmp_1)) == NULL)
		goto err;
	if ((tmp_2 = BN_bin2bn(&bnp256_gY[0], bnp256_gY.size(), tmp_2)) == NULL)
		goto err;
	if (1!= EC_POINT_set_affine_coordinates_GFp(curve,generator,tmp_1,tmp_2,ctx))
		goto err;

//	std::cout << "gX: " << BN_bn2hex(tmp_1) << '\n';
//	std::cout << "gY: " << BN_bn2hex(tmp_2) << '\n';

	if ((tmp_1 = BN_bin2bn(&bnp256_order[0], bnp256_order.size(), tmp_1)) == NULL)
		goto err;
	BN_one(tmp_2);
	if (1!= EC_GROUP_set_generator(curve,generator,tmp_1,tmp_2))
		goto err;

//	std::cout << "order: " << BN_bn2hex(tmp_1) << '\n';

	ok=1;
//	std::cout << "Curve generation succeeded\n";
err:
	if (tmp_1)
		BN_free(tmp_1);
	if (tmp_2)
		BN_free(tmp_2);
	if (tmp_3)
		BN_free(tmp_3);
	if (generator)
		EC_POINT_free(generator);
	if (ctx)
		BN_CTX_free(ctx);
	if (!ok)
		{
		EC_GROUP_free(curve);
		curve = NULL;
		}
//	std::cout << "Returning to caller after generating curve\n";
	return(curve);
	}
