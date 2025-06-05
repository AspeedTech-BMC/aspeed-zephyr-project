// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
 */

#include <zephyr/kernel.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/asn1.h>
#include <mbedtls/mbedtls_config.h>
#include <ctype.h>
#include <stdio.h>
#include <libfdt.h>
#include <soc_fmc.h>
#include <fit.h>
#include <fmc_hdr.h>
#include <stor.h>

LOG_MODULE_REGISTER(fit_image_sig, CONFIG_SOC_FMC_LOG_LEVEL);

#define MAX_PUBLIC_KEY_LENGTH	1024

#define RSA2048_BYTES	(2048 / 8)
#define RSA3072_BYTES	(3072 / 8)
#define RSA4096_BYTES	(4096 / 8)

#define ECDSA256_BYTES	(256 / 8)
#define ECDSA384_BYTES	(384 / 8)

#define SHA1_SUM_LEN		20
#define SHA256_SUM_LEN		32
#define SHA256_DER_LEN		19
#define SHA384_SUM_LEN		48
#define SHA384_DER_LEN		19
#define SHA512_SUM_LEN		64
#define SHA512_DER_LEN		19
#define SHA512_BLOCK_SIZE	128

#define CHUNKSZ_SHA384	(16 * 1024)
#define CHUNKSZ_SHA512	(16 * 1024)

struct hash_algo {
	char *name;
	uint32_t len;
	mbedtls_md_type_t md_alg;
	int (*calculate)(const unsigned char *input,
			unsigned int len,
			unsigned char *output,
			int is384);
	int is384;
	char *data;
};

struct crypto_algo {
	char *name;
	int fmc_type;
	int pk_len;
	int (*verify)(mbedtls_pk_context *pk,
			struct hash_algo *hash,
			const char *sig);
};

int rsa_verify(mbedtls_pk_context *pk,
	       struct hash_algo *hash,
	       const char *sig)
{
	mbedtls_rsa_context *rsa;
	int ret = -1;

	ret = mbedtls_pk_can_do(pk, MBEDTLS_PK_RSA);
	if (!ret) {
		LOG_DBG("PK failed");
		return ret;
	}

	rsa = mbedtls_pk_rsa(*pk);
	if (!rsa)
		return -1;

	ret = mbedtls_rsa_rsassa_pkcs1_v15_verify(rsa, hash->md_alg, hash->len, hash->data, sig);
	if (ret)
		LOG_DBG("mbedtls_rsa_rsassa_pkcs1_v15_verify failed, ret=%d", ret);
	else
		LOG_DBG("mbedtls_rsa_rsassa_pkcs1_v15_verify PASS");

	return ret;
}

int ecdsa_verify(mbedtls_pk_context *pk,
		 struct hash_algo *hash,
		 const char *sig)
{
	mbedtls_ecdsa_context ctx;
	mbedtls_mpi r, s;
	int ret;

	mbedtls_ecdsa_init(&ctx);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	ret = mbedtls_ecdsa_from_keypair(&ctx, pk->MBEDTLS_PRIVATE(pk_ctx));
	if (ret) {
		LOG_DBG("mbedtls_ecdsa_from_keypair failed, ret=%d", ret);
		return ret;
	}

	mbedtls_ecp_group_load(&ctx.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP384R1);

	mbedtls_mpi_read_binary(&r, (uint8_t *)sig, 48);
	mbedtls_mpi_read_binary(&s, (uint8_t *)sig + 48, 48);

	ret = mbedtls_ecdsa_verify(
			&ctx.MBEDTLS_PRIVATE(grp),
			hash->data, hash->len,
			&ctx.MBEDTLS_PRIVATE(Q),
			&r, &s);
	if (ret)
		LOG_DBG("mbedtls_ecdsa_verify failed, ret=%d", ret);
	else
		LOG_DBG("mbedtls_ecdsa_verify PASS, ret=%d", ret);

	mbedtls_ecdsa_free(&ctx);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);

	return 0;
}

struct crypto_algo crypto_tbl[] = {
	{"rsa4096", PBT_RSA4096_PUB_KEY, RSA4096_BYTES, rsa_verify},
	{"rsa3072", PBT_RSA3072_PUB_KEY, RSA3072_BYTES, rsa_verify},
	{"rsa2048", PBT_RSA2048_PUB_KEY, RSA2048_BYTES, rsa_verify},

	{"ecdsa384", PBT_RK384_PUB_KEY, ECDSA384_BYTES, ecdsa_verify},
	{"ecdsa256", PBT_RK256_PUB_KEY, ECDSA256_BYTES, ecdsa_verify},
};

struct hash_algo hash_tbl[] = {
	{"sha512", SHA512_SUM_LEN, MBEDTLS_MD_SHA512, mbedtls_sha512, 0},
	{"sha384", SHA384_SUM_LEN, MBEDTLS_MD_SHA384, mbedtls_sha512, 1},
	{"sha256", SHA256_SUM_LEN, MBEDTLS_MD_SHA256, mbedtls_sha256, 0},
	{"sha1",   SHA1_SUM_LEN,   MBEDTLS_MD_SHA1, NULL, 0},
};

struct hash_algo *fit_get_hash_algo(const char *full_name)
{
	const char *name;
	int i;

	for (i = 0; i < ARRAY_SIZE(hash_tbl); i++) {
		name = hash_tbl[i].name;

		/* Make sure names match and next char is a comma */
		if (!strncmp(name, full_name, strlen(name)) &&
			full_name[strlen(name)] == ',')
			return &hash_tbl[i];
	}

	return NULL;
}

struct crypto_algo *fit_get_crypto_algo(const char *full_name)
{
	const char *name;
	int i;

	/* Move name to after the comma */
	name = strchr(full_name, ',');
	if (!name)
		return NULL;
	name += 1;

	for (i = 0; i < ARRAY_SIZE(crypto_tbl); i++) {
		if (!strcmp(name, crypto_tbl[i].name)) {
			LOG_DBG("Found %s", crypto_tbl[i].name);
			return &crypto_tbl[i];
		}
	}

	return NULL;
}

int fit_parse_public_key(mbedtls_pk_context *pk, struct crypto_algo *crypto)
{
	uint32_t key_start = 0, key_len = 0;
	char pkey[MAX_PUBLIC_KEY_LENGTH] = {0};
	int ret;

	/* Get public key position from Aspeed FMC header */
	ret = fmc_hdr_get_prebuilt(crypto->fmc_type, &key_start, &key_len, NULL);
	if (ret) {
		LOG_DBG("fmc_hdr_get_prebuilt failed, ret=%d\n", ret);
		return ret;
	}

	/* Copy from storages to destination by common API stor_copy */
	soc_fmc_obj.stor_copy((uint32_t *)pkey, key_start, key_len);

	/* Parse key if it is legal or not. Key data will be saved to pk object */
	mbedtls_pk_init(pk);
	ret = mbedtls_pk_parse_public_key(pk, pkey, key_len);
	if (ret) {
		LOG_DBG("mbedtls_pk_parse_public_key failed, ret=%d", ret);
		return ret;
	}

	LOG_DBG("key_len=%d", key_len);
	LOG_DBG("Pub key[0]=0x%x", *((uint32_t *)pkey + 0));
	LOG_DBG("Pub key[1]=0x%x", *((uint32_t *)pkey + 1));
	LOG_DBG("Pub key[2]=0x%x", *((uint32_t *)pkey + 2));
	LOG_DBG("Pub key[3]=0x%x", *((uint32_t *)pkey + 3));

	return ret;
}

int fit_calculate_hash(const char *algo_name,
			const char *data,
			int data_len,
			struct hash_algo **hash,
			char *hbuf)
{
	struct hash_algo *h;
	int ret = 0;

	h = fit_get_hash_algo(algo_name);

	LOG_DBG("Found %s", h->name);

	/* sha1 is a special case */
	if (h && !h->calculate)
		ret = mbedtls_sha1(data, data_len, hbuf);

	if (h && h->calculate)
		ret = h->calculate(data, data_len, hbuf, h->is384);

	if (!h) {
		LOG_DBG("Unsupported Hash Algo!!");
		return -1;
	}

	if (ret) {
		LOG_DBG("%s hash calculation failed", h->name);
		return -2;
	}

	h->data = hbuf;
	*hash = h;

	return ret;
}

int fit_verify_sig(const void *fit, int noffset, void *data, int size)
{
	const char *algo_name;
	uint8_t *sig;
	struct crypto_algo *crypto;
	struct hash_algo *hash;
	mbedtls_pk_context pk;
	char hbuf[64] = {0};
	int sig_len;
	int ret;

	/* Get algo full name */
	if (fit_image_hash_get_algo(fit, noffset, &algo_name)) {
		LOG_DBG("Can't get hash algo property");
		return -1;
	}

	/* Get signature */
	if (fit_image_hash_get_value(fit, noffset, &sig, &sig_len)) {
		LOG_DBG("Can't get value property");
		return -3;
	}

	crypto = fit_get_crypto_algo(algo_name);
	if (!crypto) {
		LOG_DBG("%s is not supported!", crypto->name);
		return -4;
	}

	/* Parse key if it is legal or not then save to pk */
	ret = fit_parse_public_key(&pk, crypto);
	if (ret) {
		LOG_DBG("fit_parse_public_key failed, ret=%d", ret);
		goto free;
	}

	/* Turn a message to a hash */
	ret = fit_calculate_hash(algo_name, data, size, &hash, hbuf);
	if (ret) {
		LOG_DBG("fit_calculate_hash failed, ret=%d", ret);
		goto free;
	}

	/* Verify signature with key and hash */
	ret = crypto->verify(&pk, hash, sig);

free:
	mbedtls_pk_free(&pk);

	return ret;
}

int fit_verify_image(const void *fit, int image_offset, void *data, int size)
{
	const char *name;
	int noffset = 0;
	int verified = 0;
	int ret = -1;

	fdt_for_each_subnode(noffset, fit, image_offset) {
		name = fdt_get_name(fit, noffset, NULL);

		if (!strncmp(name, FIT_SIG_NODENAME,
			     strlen(FIT_SIG_NODENAME))) {
			LOG_DBG("Found prop signature!");

			ret = fit_verify_sig(fit, noffset, data, size);
			if (!ret) {
				verified = 1;
				break;
			}

		} else if (!strncmp(name, FIT_HASH_NODENAME,
				    strlen(FIT_HASH_NODENAME))) {
			LOG_DBG("Found prop hash!");
			//ret = fit_verify_hash();
		}
	}

	if (noffset == -FDT_ERR_TRUNCATED || noffset == -FDT_ERR_BADSTRUCTURE) {
		LOG_DBG("Corrupted or truncated tree");
		return -1;
	}

	return verified ? 0 : ret;
}
