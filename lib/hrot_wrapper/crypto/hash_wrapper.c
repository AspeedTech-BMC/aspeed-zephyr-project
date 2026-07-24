/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <crypto/hash.h>
#include "hash_wrapper.h"

#if defined(CONFIG_HROT_HASH_BACKEND_ASPEED)
#include <crypto/hash_aspeed.h>
#elif defined(CONFIG_HROT_HASH_BACKEND_MBEDTLS)
#if !defined(CONFIG_MBEDTLS_CFG_FILE)
#include <mbedtls/config.h>
#else
#include CONFIG_MBEDTLS_CFG_FILE
#endif
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#elif defined(CONFIG_HROT_HASH_BACKEND_CPTRA)
#include <zephyr/sys/printk.h>
#include <zephyr/crypto/crypto.h>
#include <zephyr/crypto/hash.h>
#include <zephyr/drivers/misc/aspeed/cptra_mci_mbox.h>
#endif

#if defined(CONFIG_HROT_HASH_BACKEND_ASPEED)
static int hash_wrapper_calculate_sha256(struct hash_engine *engine, const uint8_t *data,
					 size_t length, uint8_t *hash, size_t hash_length)
{
	enum hash_algo shaAlgo = CRYPTO_HASH_ALGO_SHA256;

	return hash_engine_sha_calculate(shaAlgo, data, length, hash, hash_length);
}

static int hash_wrapper_start_sha256(struct hash_engine *engine)
{
	enum hash_algo shaAlgo = CRYPTO_HASH_ALGO_SHA256;

	return hash_engine_start(shaAlgo);
}

static int hash_wrapper_calculate_sha384(struct hash_engine *engine, const uint8_t *data,
					 size_t length, uint8_t *hash, size_t hash_length)
{
	enum hash_algo shaAlgo = CRYPTO_HASH_ALGO_SHA384;

	return hash_engine_sha_calculate(shaAlgo, data, length, hash, hash_length);
}

static int hash_wrapper_start_sha384(struct hash_engine *engine)
{
	enum hash_algo shaAlgo = CRYPTO_HASH_ALGO_SHA384;

	return hash_engine_start(shaAlgo);
}

static int hash_wrapper_update(struct hash_engine *engine, const uint8_t *data, size_t length)
{
	return hash_engine_update(data, length);
}

static int hash_wrapper_finish(struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	return hash_engine_finish(hash, hash_length);
}

static void hash_wrapper_cancel(struct hash_engine *engine)
{
	hash_engine_cancel();
}
#elif defined(CONFIG_HROT_HASH_BACKEND_MBEDTLS)
static struct {
	uint8_t active;
	mbedtls_sha256_context sha256;
	mbedtls_sha512_context sha512;
} hash_wrapper_mbedtls = {
	.active = HASH_ACTIVE_NONE,
};

static void hash_wrapper_mbedtls_free_context(void)
{
	switch (hash_wrapper_mbedtls.active) {
	case HASH_ACTIVE_SHA256:
		mbedtls_sha256_free(&hash_wrapper_mbedtls.sha256);
		break;
	case HASH_ACTIVE_SHA384:
		mbedtls_sha512_free(&hash_wrapper_mbedtls.sha512);
		break;
	default:
		break;
	}

	hash_wrapper_mbedtls.active = HASH_ACTIVE_NONE;
}

static int hash_wrapper_calculate_sha256(struct hash_engine *engine, const uint8_t *data,
					 size_t length, uint8_t *hash, size_t hash_length)
{
	mbedtls_sha256_context ctx;
	int status;

	if ((engine == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

#if defined(CONFIG_HROT_HASH_MBEDTLS_BYPASS)
	hash_wrapper_mbedtls.active = HASH_ACTIVE_NONE;
	return 0;
#endif

	hash_wrapper_mbedtls_free_context();

	mbedtls_sha256_init(&ctx);
	status = mbedtls_sha256_starts(&ctx, 0);
	if (!status && length) {
		status = mbedtls_sha256_update(&ctx, data, length);
	}
	if (!status) {
		status = mbedtls_sha256_finish(&ctx, hash);
	}
	mbedtls_sha256_free(&ctx);

	return status;
}

static int hash_wrapper_start_sha256(struct hash_engine *engine)
{
	int status;

	if (engine == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (hash_wrapper_mbedtls.active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

#if defined(CONFIG_HROT_HASH_MBEDTLS_BYPASS)
	hash_wrapper_mbedtls.active = HASH_ACTIVE_SHA256;
	return 0;
#endif

	mbedtls_sha256_init(&hash_wrapper_mbedtls.sha256);
	status = mbedtls_sha256_starts(&hash_wrapper_mbedtls.sha256, 0);
	if (status) {
		mbedtls_sha256_free(&hash_wrapper_mbedtls.sha256);
		return status;
	}

	hash_wrapper_mbedtls.active = HASH_ACTIVE_SHA256;
	return 0;
}

static int hash_wrapper_calculate_sha384(struct hash_engine *engine, const uint8_t *data,
					 size_t length, uint8_t *hash, size_t hash_length)
{
	mbedtls_sha512_context ctx;
	int status;

	if ((engine == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (hash_length < SHA384_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

#if defined(CONFIG_HROT_HASH_MBEDTLS_BYPASS)
	hash_wrapper_mbedtls.active = HASH_ACTIVE_NONE;
	return 0;
#endif

	hash_wrapper_mbedtls_free_context();

	mbedtls_sha512_init(&ctx);
	status = mbedtls_sha512_starts(&ctx, 1);
	if (!status && length) {
		status = mbedtls_sha512_update(&ctx, data, length);
	}
	if (!status) {
		status = mbedtls_sha512_finish(&ctx, hash);
	}
	mbedtls_sha512_free(&ctx);

	return status;
}

static int hash_wrapper_start_sha384(struct hash_engine *engine)
{
	int status;

	if (engine == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (hash_wrapper_mbedtls.active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

#if defined(CONFIG_HROT_HASH_MBEDTLS_BYPASS)
	hash_wrapper_mbedtls.active = HASH_ACTIVE_SHA384;
	return 0;
#endif

	mbedtls_sha512_init(&hash_wrapper_mbedtls.sha512);
	status = mbedtls_sha512_starts(&hash_wrapper_mbedtls.sha512, 1);
	if (status) {
		mbedtls_sha512_free(&hash_wrapper_mbedtls.sha512);
		return status;
	}

	hash_wrapper_mbedtls.active = HASH_ACTIVE_SHA384;
	return 0;
}

static int hash_wrapper_update(struct hash_engine *engine, const uint8_t *data, size_t length)
{
	if ((engine == NULL) || ((data == NULL) && (length != 0))) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (length == 0) {
		return 0;
	}

#if defined(CONFIG_HROT_HASH_MBEDTLS_BYPASS)
	return (hash_wrapper_mbedtls.active == HASH_ACTIVE_NONE) ?
		HASH_ENGINE_NO_ACTIVE_HASH : 0;
#endif

	switch (hash_wrapper_mbedtls.active) {
	case HASH_ACTIVE_SHA256:
		return mbedtls_sha256_update(&hash_wrapper_mbedtls.sha256, data, length);
	case HASH_ACTIVE_SHA384:
		return mbedtls_sha512_update(&hash_wrapper_mbedtls.sha512, data, length);
	default:
		return HASH_ENGINE_NO_ACTIVE_HASH;
	}
}

static int hash_wrapper_finish(struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	int status;

	if ((engine == NULL) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (hash_wrapper_mbedtls.active) {
	case HASH_ACTIVE_SHA256:
		if (hash_length < SHA256_HASH_LENGTH) {
			return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
		}
#if defined(CONFIG_HROT_HASH_MBEDTLS_BYPASS)
		status = 0;
#else
		status = mbedtls_sha256_finish(&hash_wrapper_mbedtls.sha256, hash);
#endif
		break;
	case HASH_ACTIVE_SHA384:
		if (hash_length < SHA384_HASH_LENGTH) {
			return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
		}
#if defined(CONFIG_HROT_HASH_MBEDTLS_BYPASS)
		status = 0;
#else
		status = mbedtls_sha512_finish(&hash_wrapper_mbedtls.sha512, hash);
#endif
		break;
	default:
		return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	if (!status) {
		hash_wrapper_mbedtls_free_context();
	}

	return status;
}

static void hash_wrapper_cancel(struct hash_engine *engine)
{
	if (engine != NULL) {
		hash_wrapper_mbedtls_free_context();
	}
}
#elif defined(CONFIG_HROT_HASH_BACKEND_CPTRA)
/*
 * The Caliptra-SS MCI mailbox SHA engine (cptra_mci_sha) only implements
 * SHA-384/SHA-512 (see cptra_mci_sha_session_setup()), so calculate_sha256/
 * start_sha256 just print a warning and fail rather than silently doing
 * nothing. Callers that need SHA-256 (e.g. PFR provisioning's root key hash)
 * are not supported on this backend yet.
 */
static int hash_wrapper_calculate_sha256(struct hash_engine *engine, const uint8_t *data,
					 size_t length, uint8_t *hash, size_t hash_length)
{
	ARG_UNUSED(engine);
	ARG_UNUSED(data);
	ARG_UNUSED(length);
	ARG_UNUSED(hash);
	ARG_UNUSED(hash_length);

	printk("hash_wrapper: SHA-256 not supported by the CPTRA backend\n");
	return HASH_ENGINE_UNSUPPORTED_HASH;
}

static int hash_wrapper_start_sha256(struct hash_engine *engine)
{
	ARG_UNUSED(engine);

	printk("hash_wrapper: SHA-256 not supported by the CPTRA backend\n");
	return HASH_ENGINE_UNSUPPORTED_HASH;
}

static const struct device *hash_wrapper_cptra_dev(void)
{
	return DEVICE_DT_GET_ANY(aspeed_cptra_mci_sha);
}

static struct {
	uint8_t active;
	struct hash_ctx ctx;
} hash_wrapper_cptra = {
	.active = HASH_ACTIVE_NONE,
};

static void hash_wrapper_cptra_free_context(void)
{
	const struct device *dev = hash_wrapper_cptra_dev();

	if ((hash_wrapper_cptra.active != HASH_ACTIVE_NONE) && (dev != NULL)) {
		hash_free_session(dev, &hash_wrapper_cptra.ctx);
	}

	hash_wrapper_cptra.active = HASH_ACTIVE_NONE;
}

static int hash_wrapper_calculate_sha384(struct hash_engine *engine, const uint8_t *data,
					 size_t length, uint8_t *hash, size_t hash_length)
{
	const struct device *dev = hash_wrapper_cptra_dev();
	struct hash_ctx ctx = { 0 };
	struct hash_pkt pkt = { 0 };
	int status;

	if ((engine == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (hash_length < SHA384_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	if (dev == NULL) {
		return HASH_ENGINE_HW_NOT_INIT;
	}

	/* A streaming session left open by start_sha384() takes priority. */
	hash_wrapper_cptra_free_context();

	ctx.flags = crypto_query_hwcaps(dev);
	status = hash_begin_session(dev, &ctx, CRYPTO_HASH_ALGO_SHA384);
	if (status) {
		return HASH_ENGINE_START_SHA384_FAILED;
	}

	pkt.in_buf = (uint8_t *)data;
	pkt.in_len = length;
	pkt.out_buf = hash;
	status = hash_compute(&ctx, &pkt);

	hash_free_session(dev, &ctx);

	return status ? HASH_ENGINE_SHA384_FAILED : 0;
}

static int hash_wrapper_start_sha384(struct hash_engine *engine)
{
	const struct device *dev = hash_wrapper_cptra_dev();
	int status;

	if (engine == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (dev == NULL) {
		return HASH_ENGINE_HW_NOT_INIT;
	}

	if (hash_wrapper_cptra.active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	hash_wrapper_cptra.ctx.flags = crypto_query_hwcaps(dev);
	status = hash_begin_session(dev, &hash_wrapper_cptra.ctx, CRYPTO_HASH_ALGO_SHA384);
	if (status) {
		return HASH_ENGINE_START_SHA384_FAILED;
	}

	hash_wrapper_cptra.active = HASH_ACTIVE_SHA384;
	return 0;
}

static int hash_wrapper_update(struct hash_engine *engine, const uint8_t *data, size_t length)
{
	struct hash_pkt pkt = { 0 };

	if ((engine == NULL) || ((data == NULL) && (length != 0))) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (length == 0) {
		return 0;
	}

	if (hash_wrapper_cptra.active != HASH_ACTIVE_SHA384) {
		return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	pkt.in_buf = (uint8_t *)data;
	pkt.in_len = length;

	return hash_update(&hash_wrapper_cptra.ctx, &pkt) ? HASH_ENGINE_UPDATE_FAILED : 0;
}

static int hash_wrapper_finish(struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	const struct device *dev = hash_wrapper_cptra_dev();
	struct hash_pkt pkt = { 0 };
	int status;

	if ((engine == NULL) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (hash_wrapper_cptra.active != HASH_ACTIVE_SHA384) {
		return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	if (hash_length < SHA384_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	pkt.out_buf = hash;
	status = hash_compute(&hash_wrapper_cptra.ctx, &pkt);

	hash_free_session(dev, &hash_wrapper_cptra.ctx);
	hash_wrapper_cptra.active = HASH_ACTIVE_NONE;

	return status ? HASH_ENGINE_FINISH_FAILED : 0;
}

static void hash_wrapper_cancel(struct hash_engine *engine)
{
	if (engine != NULL) {
		hash_wrapper_cptra_free_context();
	}
}
#endif

/**
 * Initialize a hash engine wrapper.
 *
 * @param engine The hash engine to initialize.
 *
 * @return 0 if the hash engine was successfully initialized or an error code.
 */
int hash_wrapper_init(struct hash_engine *engine)
{
	if (engine == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	memset(engine, 0, sizeof(struct hash_engine));

	engine->calculate_sha256 = hash_wrapper_calculate_sha256;
	engine->start_sha256 = hash_wrapper_start_sha256;
	engine->calculate_sha384 = hash_wrapper_calculate_sha384;
	engine->start_sha384 = hash_wrapper_start_sha384;
	engine->update = hash_wrapper_update;
	engine->finish = hash_wrapper_finish;
	engine->cancel = hash_wrapper_cancel;

#if defined(CONFIG_HROT_HASH_BACKEND_MBEDTLS)
	hash_wrapper_mbedtls_free_context();
#elif defined(CONFIG_HROT_HASH_BACKEND_CPTRA)
	hash_wrapper_cptra_free_context();
#endif

	return 0;
}
