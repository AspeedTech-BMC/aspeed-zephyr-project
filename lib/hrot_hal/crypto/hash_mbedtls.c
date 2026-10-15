/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * hash_engine_* on mbedTLS software SHA-256/SHA-384, for SoCs without a
 * hardware hash engine.
 */

#include <errno.h>
#include <stdbool.h>
#if !defined(CONFIG_MBEDTLS_CFG_FILE)
#include <mbedtls/config.h>
#else
#include CONFIG_MBEDTLS_CFG_FILE
#endif
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include "hash_aspeed.h"

static struct {
	enum hash_algo algo;
	bool active;
	union {
		mbedtls_sha256_context sha256;
		mbedtls_sha512_context sha512;
	};
} session;

static size_t digest_size(enum hash_algo algo)
{
	switch (algo) {
	case CRYPTO_HASH_ALGO_SHA256:
		return 32;
	case CRYPTO_HASH_ALGO_SHA384:
		return 48;
	default:
		return 0;
	}
}

int hash_engine_start(enum hash_algo algo)
{
	int ret;

	if (!digest_size(algo))
		return -ENOTSUP;
	if (session.active)
		return -EBUSY;

	session.algo = algo;
	if (algo == CRYPTO_HASH_ALGO_SHA256) {
		mbedtls_sha256_init(&session.sha256);
		ret = mbedtls_sha256_starts(&session.sha256, 0);
	} else {
		mbedtls_sha512_init(&session.sha512);
		ret = mbedtls_sha512_starts(&session.sha512, 1);
	}

	session.active = true;
	if (ret)
		hash_engine_cancel();
	return ret;
}

int hash_engine_update(const uint8_t *data, size_t length)
{
	if (data == NULL && length != 0)
		return -EINVAL;
	if (!session.active)
		return -ENOENT;
	if (!length)
		return 0;

	if (session.algo == CRYPTO_HASH_ALGO_SHA256)
		return mbedtls_sha256_update(&session.sha256, data, length);
	return mbedtls_sha512_update(&session.sha512, data, length);
}

int hash_engine_finish(uint8_t *hash, size_t hash_length)
{
	int ret;

	if (hash == NULL)
		return -EINVAL;
	if (!session.active)
		return -ENOENT;
	if (hash_length < digest_size(session.algo))
		return -ENOSPC;

	if (session.algo == CRYPTO_HASH_ALGO_SHA256)
		ret = mbedtls_sha256_finish(&session.sha256, hash);
	else
		ret = mbedtls_sha512_finish(&session.sha512, hash);

	/* A failed finish may be retried or cancelled by the caller. */
	if (!ret)
		hash_engine_cancel();
	return ret;
}

void hash_engine_cancel(void)
{
	if (!session.active)
		return;

	if (session.algo == CRYPTO_HASH_ALGO_SHA256)
		mbedtls_sha256_free(&session.sha256);
	else
		mbedtls_sha512_free(&session.sha512);
	session.active = false;
}

int hash_engine_sha_calculate(enum hash_algo algo, const uint8_t *data,
			      size_t length, uint8_t *hash, size_t hash_length)
{
	int ret;

	if (hash == NULL || (data == NULL && length != 0))
		return -EINVAL;
	if (!digest_size(algo))
		return -ENOTSUP;
	if (hash_length < digest_size(algo))
		return -ENOSPC;

	/* A one-shot calculation replaces any streaming operation. */
	hash_engine_cancel();

	ret = hash_engine_start(algo);
	if (ret)
		return ret;

	ret = hash_engine_update(data, length);
	if (!ret)
		ret = hash_engine_finish(hash, hash_length);
	hash_engine_cancel();
	return ret;
}
