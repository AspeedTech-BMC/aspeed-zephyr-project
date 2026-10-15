/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * hash_engine_* on the Caliptra-SS MCI SHA_ACC engine. SHA_ACC DMA-reads its
 * source, so input buffers are flushed and passed as bus addresses. Only
 * SHA-384 and SHA-512 are implemented by the engine.
 */

#include <errno.h>
#include <string.h>
#include <zephyr/cache.h>
#include <zephyr/device.h>
#include <zephyr/crypto/crypto.h>
#include <soc.h>
#include "hash_aspeed.h"

static struct {
	struct hash_ctx ctx;
	size_t digest_size;
	bool active;
} session;

static size_t digest_size(enum hash_algo algo)
{
	switch (algo) {
	case CRYPTO_HASH_ALGO_SHA384:
		return 48;
	case CRYPTO_HASH_ALGO_SHA512:
		return 64;
	default:
		return 0;
	}
}

/* Publish CPU writes before the engine DMA-reads the buffer. */
static uint8_t *dma_source(const uint8_t *data, size_t length)
{
	sys_cache_data_flush_range((void *)data, length);
	return (uint8_t *)(uintptr_t)TO_PHY_ADDR((uintptr_t)data);
}

int hash_engine_start(enum hash_algo algo)
{
	const struct device *dev = DEVICE_DT_GET_ANY(aspeed_cptra_mci_sha_acc);
	size_t size = digest_size(algo);
	int ret;

	if (!size)
		return -ENOTSUP;
	if (dev == NULL || !device_is_ready(dev))
		return -ENODEV;
	if (session.active)
		return -EBUSY;

	memset(&session.ctx, 0, sizeof(session.ctx));
	session.ctx.flags = crypto_query_hwcaps(dev);
	ret = hash_begin_session(dev, &session.ctx, algo);
	if (ret)
		return ret;

	session.digest_size = size;
	session.active = true;
	return 0;
}

int hash_engine_update(const uint8_t *data, size_t length)
{
	struct hash_pkt pkt = { 0 };

	if (data == NULL && length != 0)
		return -EINVAL;
	if (!session.active)
		return -ENOENT;
	if (!length)
		return 0;

	pkt.in_buf = dma_source(data, length);
	pkt.in_len = length;
	return hash_update(&session.ctx, &pkt);
}

int hash_engine_finish(uint8_t *hash, size_t hash_length)
{
	/* Input was consumed by update; an empty packet keeps SHA_ACC from
	 * hashing the last chunk a second time.
	 */
	struct hash_pkt pkt = { .out_buf = hash };
	int ret;

	if (hash == NULL)
		return -EINVAL;
	if (!session.active)
		return -ENOENT;
	if (hash_length < session.digest_size)
		return -ENOSPC;

	ret = hash_compute(&session.ctx, &pkt);
	hash_engine_cancel();
	return ret;
}

void hash_engine_cancel(void)
{
	if (!session.active)
		return;

	hash_free_session(session.ctx.device, &session.ctx);
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
	if (ret) {
		hash_engine_cancel();
		return ret;
	}

	return hash_engine_finish(hash, hash_length);
}
