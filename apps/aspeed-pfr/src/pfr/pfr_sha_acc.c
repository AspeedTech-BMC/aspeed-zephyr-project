/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * SHA-384 a flash region on the Caliptra SHA_ACC engine. SHA_ACC keeps its
 * session open across UPDATEs, so large chunks are hashed per mailbox call
 * instead of the generic path's 4 KB block per hash call (~11700 mailbox
 * round-trips for a 45 MB image). Chunks are double-buffered in the IO SRAM
 * so the flash read of one chunk overlaps SHA_ACC on the previous one.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include "pfr_sha_acc.h"

#if defined(CONFIG_CPTRA_MCI_SHA_ACC)

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/crypto/crypto.h>
#include <zephyr/crypto/hash.h>
#include <soc.h>

#define SHA_ACC_SHA384_DIGEST_SIZE	48

/*
 * AST1080 IO SRAM: SPI DMA fills it ~3.6x faster than HyperRAM. Caliptra's
 * AXI sees AHB 0x1xxx_xxxx at 0x3xxx_xxxx (caliptra-mcu-sw
 * platforms/ast1040/config/src/peri.rs), so SHA_ACC needs the bus address
 * moved up by 0x2000_0000.
 */
BUILD_ASSERT(DT_NODE_EXISTS(DT_NODELABEL(sram_buf)),
	     "SHA_ACC verify path stages flash data in the sram_buf IO SRAM");

#define SHA_ACC_SRAM			((uint8_t *)DT_REG_ADDR(DT_NODELABEL(sram_buf)))
/* Two back-to-back buffers at the start of sram_buf; a cache-line multiple so both can DMA. */
#define SHA_ACC_PIPE_CHUNK		(32UL * 1024)

BUILD_ASSERT(SHA_ACC_PIPE_CHUNK % CONFIG_DCACHE_LINE_SIZE == 0 &&
	     2 * SHA_ACC_PIPE_CHUNK <= DT_REG_SIZE(DT_NODELABEL(sram_buf)),
	     "SHA_ACC pipe buffers must be cache-line sized and fit in sram_buf");
#define SHA_ACC_AXI_ADDR(buf)		(TO_PHY_ADDR((uintptr_t)(buf)) + 0x20000000UL)

/* From pfr_util.h, which cannot be included here (Cerberus hash.h clash). */
int pfr_spi_read(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data);

/* ---- double-buffered read + SHA_ACC pipeline ---- */

#define SHA_ACC_PIPE_STACK_SIZE		2048
#define SHA_ACC_PIPE_MAX_BUFS		8

/* Fills @buf from flash; the boot path and flash_perf read different ways. */
typedef int (*sha_acc_pipe_read_fn)(const void *src, uint32_t addr, uint8_t *buf, uint32_t len);

struct sha_acc_pipe_job {
	uint8_t buf_id;
	uint32_t len;
	bool last;
};

struct sha_acc_pipe {
	struct hash_ctx ctx;
	const uintptr_t *sha_acc_addr;
	uint8_t *hash_out;
	uint32_t hash_ms;
	int hash_ret;
	struct k_msgq free_q;	/* buffer ids ready to be filled from flash */
	struct k_msgq hash_q;	/* filled buffers waiting for SHA_ACC */
	uint8_t free_q_buf[SHA_ACC_PIPE_MAX_BUFS * sizeof(uint8_t)];
	uint8_t hash_q_buf[SHA_ACC_PIPE_MAX_BUFS * sizeof(struct sha_acc_pipe_job)] __aligned(4);
};

/*
 * Owns sram_buf, which has no allocator: the verify path and every test
 * command staging data there hold it (pfr_sha_acc_sram_lock()). It also
 * serializes the pipeline's worker thread and stack. Recursive, so callers
 * may already hold it.
 */
static K_MUTEX_DEFINE(sha_acc_sram_lock);
static struct sha_acc_pipe sha_acc_pipe;
static struct k_thread sha_acc_pipe_thread;
static K_THREAD_STACK_DEFINE(sha_acc_pipe_stack, SHA_ACC_PIPE_STACK_SIZE);

/*
 * Hashes filled buffers in order and hands them back. Stops after the job
 * marked last; once a hash fails it only drains, so the session still ends.
 */
static void sha_acc_pipe_worker(void *p1, void *p2, void *p3)
{
	struct sha_acc_pipe *pipe = p1;
	struct sha_acc_pipe_job job;
	struct hash_pkt pkt = { 0 };
	uint32_t t0;

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	do {
		k_msgq_get(&pipe->hash_q, &job, K_FOREVER);

		if (pipe->hash_ret == 0 && job.len > 0) {
			/* in_buf is Caliptra's AXI address of the source, not a CPU pointer. */
			pkt.in_buf = (uint8_t *)pipe->sha_acc_addr[job.buf_id];
			pkt.in_len = job.len;

			/* First call is INIT, the rest UPDATE, the last adds FINAL. */
			t0 = k_uptime_get_32();
			if (job.last) {
				pkt.out_buf = pipe->hash_out;
				pipe->hash_ret = hash_compute(&pipe->ctx, &pkt);
			} else {
				pipe->hash_ret = hash_update(&pipe->ctx, &pkt);
			}
			pipe->hash_ms += k_uptime_get_32() - t0;
		}

		/* Publishes hash_ret too: the reader only reads it after a free_q get. */
		k_msgq_put(&pipe->free_q, &job.buf_id, K_FOREVER);
	} while (!job.last);
}

static int sha_acc_pipe_run(sha_acc_pipe_read_fn read, const void *src, uint32_t offset,
			    uint32_t length, uint8_t *const buf[], const uintptr_t sha_acc_addr[],
			    uint8_t nbuf, uint32_t chunk_max, uint8_t *hash_out,
			    uint32_t *read_ms, uint32_t *hash_ms)
{
	const struct device *dev = DEVICE_DT_GET_ANY(aspeed_cptra_mci_sha_acc);
	struct sha_acc_pipe *pipe = &sha_acc_pipe;
	struct sha_acc_pipe_job job;
	uint32_t addr = offset;
	uint32_t remaining = length;
	uint32_t t0;
	uint8_t id;
	int prio;
	int ret;

	prio = k_thread_priority_get(k_current_get());

	*read_ms = 0;
	*hash_ms = 0;

	if (nbuf < 2 || nbuf > SHA_ACC_PIPE_MAX_BUFS)
		return -EINVAL;

	if (dev == NULL || !device_is_ready(dev))
		return -ENODEV;

	k_mutex_lock(&sha_acc_sram_lock, K_FOREVER);

	memset(pipe, 0, sizeof(*pipe));
	pipe->sha_acc_addr = sha_acc_addr;
	pipe->hash_out = hash_out;
	k_msgq_init(&pipe->free_q, pipe->free_q_buf, sizeof(uint8_t), nbuf);
	k_msgq_init(&pipe->hash_q, pipe->hash_q_buf, sizeof(struct sha_acc_pipe_job), nbuf);
	for (id = 0; id < nbuf; id++)
		k_msgq_put(&pipe->free_q, &id, K_NO_WAIT);

	pipe->ctx.flags = crypto_query_hwcaps(dev);
	ret = hash_begin_session(dev, &pipe->ctx, CRYPTO_HASH_ALGO_SHA384);
	if (ret)
		goto unlock;

	/*
	 * The worker runs one step below the reader, so a finished DMA can start
	 * the next read while SHA_ACC busy-polls the mailbox. A caller already at
	 * the lowest priority (the shell) is raised for the run instead; at equal
	 * priority, with no time slicing, reads would wait for each hash call.
	 */
	if (prio >= K_LOWEST_APPLICATION_THREAD_PRIO)
		k_thread_priority_set(k_current_get(), K_LOWEST_APPLICATION_THREAD_PRIO - 1);
	k_thread_create(&sha_acc_pipe_thread, sha_acc_pipe_stack,
			K_THREAD_STACK_SIZEOF(sha_acc_pipe_stack), sha_acc_pipe_worker,
			pipe, NULL, NULL, MIN(prio + 1, K_LOWEST_APPLICATION_THREAD_PRIO), 0,
			K_NO_WAIT);
	k_thread_name_set(&sha_acc_pipe_thread, "sha_acc_pipe");

	do {
		k_msgq_get(&pipe->free_q, &id, K_FOREVER);

		job.buf_id = id;
		job.len = MIN(remaining, chunk_max);

		if (ret == 0 && pipe->hash_ret == 0) {
			t0 = k_uptime_get_32();
			ret = read(src, addr, buf[id], job.len);
			*read_ms += k_uptime_get_32() - t0;
		}

		addr += job.len;
		remaining -= job.len;

		/* On any error, tell the worker to stop after this (unhashed) job. */
		if (ret || pipe->hash_ret) {
			job.len = 0;
			remaining = 0;
		}
		job.last = (remaining == 0);

		k_msgq_put(&pipe->hash_q, &job, K_FOREVER);
	} while (remaining > 0);

	k_thread_join(&sha_acc_pipe_thread, K_FOREVER);
	k_thread_priority_set(k_current_get(), prio);
	*hash_ms = pipe->hash_ms;

	hash_free_session(dev, &pipe->ctx);

	if (ret == 0)
		ret = pipe->hash_ret;
unlock:
	k_mutex_unlock(&sha_acc_sram_lock);

	return ret;
}

void pfr_sha_acc_sram_lock(void)
{
	k_mutex_lock(&sha_acc_sram_lock, K_FOREVER);
}

void pfr_sha_acc_sram_unlock(void)
{
	k_mutex_unlock(&sha_acc_sram_lock);
}

static int sha_acc_pfr_spi_read(const void *src, uint32_t addr, uint8_t *buf, uint32_t len)
{
	return pfr_spi_read(*(const uint8_t *)src, addr, len, buf);
}

int pfr_sha_acc_hash_region(uint8_t device_id, uint32_t offset, uint32_t length,
			    uint8_t *hash_out, size_t hash_length)
{
	uint8_t *const buf[2] = { SHA_ACC_SRAM, SHA_ACC_SRAM + SHA_ACC_PIPE_CHUNK };
	const uintptr_t sha_acc_addr[2] = {
		SHA_ACC_AXI_ADDR(buf[0]),
		SHA_ACC_AXI_ADDR(buf[1]),
	};
	uint32_t read_ms, hash_ms;

	if (hash_out == NULL || length == 0 || hash_length < SHA_ACC_SHA384_DIGEST_SIZE)
		return -EINVAL;

	return sha_acc_pipe_run(sha_acc_pfr_spi_read, &device_id, offset, length, buf,
				sha_acc_addr, ARRAY_SIZE(buf), SHA_ACC_PIPE_CHUNK, hash_out,
				&read_ms, &hash_ms);
}

int pfr_sha_acc_perf(const struct device *flash, uint32_t offset, uint32_t length,
		     uint8_t *buf, uintptr_t sha_acc_addr, uint32_t chunk_max,
		     uint8_t *hash_out,
		     uint32_t *read_ms, uint32_t *hash_ms)
{
	const struct device *dev = DEVICE_DT_GET_ANY(aspeed_cptra_mci_sha_acc);
	struct hash_ctx ctx = { 0 };
	struct hash_pkt pkt = { 0 };
	uint32_t src = offset;
	uint32_t remaining = length;
	uint32_t t0;
	int ret;

	*read_ms = 0;
	*hash_ms = 0;

	if (buf == NULL || hash_out == NULL || length == 0 || chunk_max == 0)
		return -EINVAL;

	if (dev == NULL || !device_is_ready(dev))
		return -ENODEV;

	k_mutex_lock(&sha_acc_sram_lock, K_FOREVER);

	ctx.flags = crypto_query_hwcaps(dev);
	ret = hash_begin_session(dev, &ctx, CRYPTO_HASH_ALGO_SHA384);
	if (ret)
		goto unlock;

	while (remaining > 0) {
		uint32_t chunk = MIN(remaining, chunk_max);

		t0 = k_uptime_get_32();
		ret = flash_read(flash, src, buf, chunk);
		*read_ms += k_uptime_get_32() - t0;
		if (ret)
			break;

		pkt.in_buf = (uint8_t *)sha_acc_addr;
		pkt.in_len = chunk;

		src += chunk;
		remaining -= chunk;

		t0 = k_uptime_get_32();
		if (remaining == 0) {
			pkt.out_buf = hash_out;
			ret = hash_compute(&ctx, &pkt);
		} else {
			ret = hash_update(&ctx, &pkt);
		}
		*hash_ms += k_uptime_get_32() - t0;

		if (ret)
			break;
	}

	hash_free_session(dev, &ctx);
unlock:
	k_mutex_unlock(&sha_acc_sram_lock);

	return ret;
}

static int sha_acc_flash_read(const void *src, uint32_t addr, uint8_t *buf, uint32_t len)
{
	return flash_read(src, addr, buf, len);
}

int pfr_sha_acc_perf_pipe(const struct device *flash, uint32_t offset, uint32_t length,
			  uint8_t *const buf[], const uintptr_t sha_acc_addr[], uint8_t nbuf,
			  uint32_t chunk_max, uint8_t *hash_out,
			  uint32_t *read_ms, uint32_t *hash_ms, uint32_t *total_ms)
{
	uint32_t t_start;
	int ret;

	*read_ms = 0;
	*hash_ms = 0;
	*total_ms = 0;

	if (buf == NULL || sha_acc_addr == NULL || hash_out == NULL || length == 0 ||
	    chunk_max == 0)
		return -EINVAL;

	t_start = k_uptime_get_32();
	ret = sha_acc_pipe_run(sha_acc_flash_read, flash, offset, length, buf, sha_acc_addr,
			       nbuf, chunk_max, hash_out, read_ms, hash_ms);
	*total_ms = k_uptime_get_32() - t_start;

	return ret;
}

#else /* !CONFIG_CPTRA_MCI_SHA_ACC */

/* No verify path uses sram_buf, so there is nothing to serialize against. */
void pfr_sha_acc_sram_lock(void)
{
}

void pfr_sha_acc_sram_unlock(void)
{
}

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

int pfr_sha_acc_perf(const struct device *flash, uint32_t offset, uint32_t length,
		     uint8_t *buf, uintptr_t sha_acc_addr, uint32_t chunk_max,
		     uint8_t *hash_out,
		     uint32_t *read_ms, uint32_t *hash_ms)
{
	ARG_UNUSED(flash);
	ARG_UNUSED(offset);
	ARG_UNUSED(length);
	ARG_UNUSED(buf);
	ARG_UNUSED(sha_acc_addr);
	ARG_UNUSED(chunk_max);
	ARG_UNUSED(hash_out);
	*read_ms = 0;
	*hash_ms = 0;

	return -ENOTSUP;
}

int pfr_sha_acc_perf_pipe(const struct device *flash, uint32_t offset, uint32_t length,
			  uint8_t *const buf[], const uintptr_t sha_acc_addr[], uint8_t nbuf,
			  uint32_t chunk_max, uint8_t *hash_out,
			  uint32_t *read_ms, uint32_t *hash_ms, uint32_t *total_ms)
{
	ARG_UNUSED(flash);
	ARG_UNUSED(offset);
	ARG_UNUSED(length);
	ARG_UNUSED(buf);
	ARG_UNUSED(sha_acc_addr);
	ARG_UNUSED(nbuf);
	ARG_UNUSED(chunk_max);
	ARG_UNUSED(hash_out);
	*read_ms = 0;
	*hash_ms = 0;
	*total_ms = 0;

	return -ENOTSUP;
}

#endif /* CONFIG_CPTRA_MCI_SHA_ACC */
