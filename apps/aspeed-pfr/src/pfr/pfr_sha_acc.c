/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * SHA-384 a flash region on the Caliptra SHA_ACC engine. SHA_ACC keeps its
 * session open across UPDATEs, so one large buffer is refilled and re-hashed
 * instead of the generic path's 4 KB block per hash call (~11700 mailbox
 * round-trips for a 45 MB image).
 */

#include <errno.h>

#include <zephyr/sys/util.h>

#include "pfr_sha_acc.h"

#if defined(CONFIG_CPTRA_MCI_SHA_ACC)

#include <zephyr/device.h>
#include <zephyr/crypto/crypto.h>
#include <zephyr/crypto/hash.h>
#include <soc.h>

#define SHA_ACC_SHA384_DIGEST_SIZE	48

/* Bytes per read + UPDATE pair; shares RAM_NC with the other DMA buffers. */
#define SHA_ACC_COPY_CHUNK		(256UL * 1024)

/*
 * RAM_NC so the flash driver DMAs straight in and Caliptra needs no flush;
 * line aligned or aspeed_spi_dma_usable() drops to the ~4x slower PIO path.
 */
static uint8_t sha_acc_buf[SHA_ACC_COPY_CHUNK]
	NON_CACHED_BSS __aligned(CONFIG_DCACHE_LINE_SIZE);

/* From pfr_util.h, which cannot be included here (Cerberus hash.h clash). */
int pfr_spi_read(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data);

int pfr_sha_acc_hash_region(uint8_t device_id, uint32_t offset, uint32_t length,
			    uint8_t *hash_out, size_t hash_length)
{
	const struct device *dev = DEVICE_DT_GET_ANY(aspeed_cptra_mci_sha_acc);
	struct hash_ctx ctx = { 0 };
	struct hash_pkt pkt = { 0 };
	uint32_t src = offset;
	uint32_t remaining = length;
	int ret;

	if (hash_out == NULL || length == 0 || hash_length < SHA_ACC_SHA384_DIGEST_SIZE)
		return -EINVAL;

	if (dev == NULL || !device_is_ready(dev))
		return -ENODEV;

	ctx.flags = crypto_query_hwcaps(dev);
	ret = hash_begin_session(dev, &ctx, CRYPTO_HASH_ALGO_SHA384);
	if (ret)
		return ret;

	while (remaining > 0) {
		uint32_t chunk = MIN(remaining, SHA_ACC_COPY_CHUNK);

		ret = pfr_spi_read(device_id, src, chunk, sha_acc_buf);
		if (ret)
			break;

		/* in_buf is the bus address of the source, not a CPU pointer. */
		pkt.in_buf = (uint8_t *)(uintptr_t)TO_PHY_ADDR((uintptr_t)sha_acc_buf);
		pkt.in_len = chunk;

		src += chunk;
		remaining -= chunk;

		/* First call is INIT, the rest UPDATE, the last adds FINAL. */
		if (remaining == 0) {
			pkt.out_buf = hash_out;
			ret = hash_compute(&ctx, &pkt);
		} else {
			ret = hash_update(&ctx, &pkt);
		}

		if (ret)
			break;
	}

	hash_free_session(dev, &ctx);

	return ret;
}

#else /* !CONFIG_CPTRA_MCI_SHA_ACC */

int pfr_sha_acc_hash_region(uint8_t device_id, uint32_t offset, uint32_t length,
			    uint8_t *hash_out, size_t hash_length)
{
	ARG_UNUSED(device_id);
	ARG_UNUSED(offset);
	ARG_UNUSED(length);
	ARG_UNUSED(hash_out);
	ARG_UNUSED(hash_length);

	return -ENOTSUP;
}

#endif /* CONFIG_CPTRA_MCI_SHA_ACC */
