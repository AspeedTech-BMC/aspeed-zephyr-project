/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <manifest.h>
#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/drivers/cptra.h>
#include <zephyr/logging/log.h>
#include <scu.h>
#include <ast_loader.h>
#include <chip.h>

LOG_MODULE_REGISTER(ast_loader, CONFIG_SOC_FMC_LOG_LEVEL);

struct ast_loader g_loader;

void *memcpy32(uint32_t *dst, uint32_t *src, uint32_t len)
{
	unsigned long *dl = (unsigned long *)dst;
	unsigned long *sl = (unsigned long *)src;
	char *d8, *s8;

	if (src == NULL || dst == NULL || len == 0) {
		LOG_ERR("mem_copy: src or dst is NULL or len is 0\n");
		return NULL;
	}

	if (src == dst) {
		LOG_DBG("mem_copy: src and dst are the same, no copy needed\n");
		return dst;
	}

	/* 4-byte aligned copy */
	if ((((unsigned long)dst | (unsigned long)src) & (sizeof(unsigned long) - 1)) == 0) {
		while (len >= sizeof(unsigned long)) {
			*dl++ = *sl++;
			len -= sizeof(unsigned long);
		}
	}

	/* Copy remaining bytes */
	d8 = (char *)dl;
	s8 = (char *)sl;

	while (len--)
		*d8++ = *s8++;

	return dst;
}

int ast_loader_read(uint32_t *dst, uint32_t src, uint32_t len)
{
	struct ast_loader *loader = &g_loader;
	struct ast_loader_ops *ops;
	int err = 0;

	LOG_DBG("%s: dst=0x%x, src=0x%x, len=0x%x\n", __func__, (uint32_t)dst, src, len);

	ops = ast_loader_get_ops(loader);
	if (ops && ops->copy) {
		err = ops->copy(loader, dst, src, len);
		if (err)
			return err;
	}

	return err;
}

/*
 * Chunked verification: images are hashed while they stream through the
 * staging buffer; the soc manifest is instead verified in place at dst
 * after the copy completes (its verify needs the whole structure).
 */
#ifdef CONFIG_CPTRA_MANIFEST_SIGNATURE
static int ast_loader_verify_begin(bool verify, uint32_t type)
{
	if (!verify || type == CPTRA_MANIFEST_FW_ID)
		return 0;

	return cptra_verify_image_init();
}

static int ast_loader_verify_update(bool verify, uint32_t type, uint8_t *data, uint32_t len)
{
	if (!verify || type == CPTRA_MANIFEST_FW_ID)
		return 0;

	return cptra_verify_image_update(data, len);
}

static int ast_loader_verify_final(bool verify, uint32_t type, uint32_t *dst)
{
	int err = 0;

	if (!verify)
		return 0;

	if (type == CPTRA_MANIFEST_FW_ID) {
#ifndef CONFIG_CPTRA_2X_LAYOUT
		/* verify's ~14KB auth_input frame stacks on the 4KB stream stage */
		BUILD_ASSERT(sizeof(struct cptra_set_auth_manifest_ia) +
			     CONFIG_AST_LOADER_SEG_BUF_SIZE + 2048 <= CONFIG_MAIN_STACK_SIZE,
			     "main stack too small for cptra_verify_soc_manifest_img()");
		err = cptra_verify_soc_manifest_img((struct cptra_soc_manifest *)dst);
		if (err)
			return err;

		err = cptra_verify_soc_manifest_ver((struct cptra_soc_manifest *)dst);
#endif
		return err;
	}

	return cptra_verify_image_final(type);
}

static void ast_loader_verify_abort(void)
{
	cptra_verify_image_abort();
}
#else
static int ast_loader_verify_begin(bool verify, uint32_t type)
{
	if (verify) {
		LOG_ERR("Verifier does not be registered.");
		return -1;
	}

	return 0;
}

static int ast_loader_verify_update(bool verify, uint32_t type, uint8_t *data, uint32_t len)
{
	return 0;
}

static int ast_loader_verify_final(bool verify, uint32_t type, uint32_t *dst)
{
	return 0;
}

static void ast_loader_verify_abort(void)
{
}
#endif

static void ast_loader_wipe(uint32_t *dst, uint32_t len)
{
	uint8_t *d8;

	while (len >= sizeof(uint32_t)) {
		*dst++ = 0;
		len -= sizeof(uint32_t);
	}

	d8 = (uint8_t *)dst;
	while (len--)
		*d8++ = 0;
}

/* Segmented load path for storage interfaces with random access (load_seg) */
static int _ast_loader_load_image_seg(uint32_t type, uint32_t *dst, uint32_t dst_check_max_len,
				      bool verify, uint32_t *img_read_size)
{
	struct ast_loader *loader = &g_loader;
	uint32_t seg_buf[CONFIG_AST_LOADER_SEG_BUF_SIZE / sizeof(uint32_t)];
	uint32_t off = 0, len, sz = 0;
	int err;

	if (!dst) {
		LOG_ERR("%s: Invalid input params", __func__);
		return -1;
	}

	err = loader->get_size(loader, type, &sz);
	if (err)
		return err;

	if (sz == 0) {
		LOG_WRN("Img size == 0");
		if (img_read_size)
			*img_read_size = 0;
		return 0;
	}

	if (dst_check_max_len != 0 && sz > dst_check_max_len) {
		LOG_ERR("Img size (0x%x) exceeds dst buf size (0x%x)", sz, dst_check_max_len);
		return -1;
	}

	LOG_INF("%s: type=%d, dst=0x%x, size=0x%x, sec boot verify=%d",
		__func__, type, (uint32_t)dst, sz, verify && cptra_manifest_sec_en());

	err = ast_loader_verify_begin(verify, type);
	if (err)
		return err;

	for (off = 0; off < sz; off += len) {
		len = MIN(sizeof(seg_buf), sz - off);

		err = loader->load_seg(loader, type, seg_buf, off, len);
		if (err)
			goto wipe;

		/* hash the staged bytes, not dst readback: MMIO dst may not read back */
		err = ast_loader_verify_update(verify, type, (uint8_t *)seg_buf, len);
		if (err)
			goto wipe;

		memcpy32(dst + off / sizeof(uint32_t), seg_buf, len);
	}

	err = ast_loader_verify_final(verify, type, dst);
	if (err) {
		LOG_ERR("%s: type %d verify failed, err=%d", __func__, type, err);
		goto wipe;
	}

	if (img_read_size)
		*img_read_size = sz;

	return 0;

wipe:
	/*
	 * dst held unverified data, scrub it before returning. off counts the
	 * bytes actually copied (== sz once the loop completes), so bytes never
	 * loaded at an MMIO/shared dst are left untouched.
	 */
	ast_loader_verify_abort();
	ast_loader_wipe(dst, off);
	return err;
}

/*
 * Streamed load path for recovery interfaces: the transport pushes payload
 * chunks into the sink append-only; full staging buffers are hashed and
 * copied to dst on the fly, so no whole-image buffer is needed.
 */
struct ast_loader_stage {
	uint32_t *dst;
	uint32_t max_len;
	uint32_t type;
	bool verify;
	bool hashing;
	uint32_t last_ofst;
	uint32_t received;
	uint32_t flushed;
	int err;
	uint32_t buf[CONFIG_AST_LOADER_SEG_BUF_SIZE / sizeof(uint32_t)];
};

static int ast_loader_stage_flush(struct ast_loader_stage *st, uint32_t len)
{
	int err;

	err = ast_loader_verify_update(st->verify, st->type, (uint8_t *)st->buf, len);
	if (err)
		return err;

	memcpy32(st->dst + st->flushed / sizeof(uint32_t), st->buf, len);
	st->flushed += len;

	return 0;
}

static int ast_loader_sink_write(struct ast_loader_sink *sink, uint32_t ofst,
				 const uint8_t *data, uint32_t len)
{
	struct ast_loader_stage *st = sink->priv;
	uint32_t staged, copy;
	int err;

	if (st->err)
		return st->err;

	/*
	 * A transport retry (e.g. DFU after a lost status stage) may resend the
	 * last write. Flushing is lazy, so unless that write straddled a flush
	 * it is still in the stage buffer, unhashed: overwrite it in place, like
	 * the old whole-image buffer did.
	 */
	if (len && ofst == st->last_ofst && ofst + len == st->received &&
	    ofst >= st->flushed) {
		memcpy((uint8_t *)st->buf + (ofst - st->flushed), data, len);
		return 0;
	}

	if (ofst != st->received) {
		LOG_ERR("%s: non-sequential write (ofst=0x%x, expect=0x%x)",
			__func__, ofst, st->received);
		st->err = -1;
		return -1;
	}

	if (st->max_len != 0 && st->received + len > st->max_len) {
		LOG_ERR("Img size (0x%x) exceeds dst buf size (0x%x)",
			st->received + len, st->max_len);
		st->err = -1;
		return -1;
	}

	/*
	 * Open the hash session on the first byte, not before loader->load():
	 * recovery transports may wait indefinitely for the host to start, and
	 * the session holds the Caliptra SHA HW lock.
	 *
	 * Known limitation: once open, the lock stays held until load() returns,
	 * including while a recovery host stalls between blocks (no transport
	 * has an inactivity timeout). Streaming SHA keeps its state in the
	 * engine, so the lock cannot be dropped between chunks; any other
	 * Caliptra SHA user waits for the image to finish or fail.
	 */
	if (len && !st->hashing) {
		err = ast_loader_verify_begin(st->verify, st->type);
		if (err) {
			st->err = err;
			return err;
		}
		st->hashing = true;
	}

	st->last_ofst = ofst;

	while (len) {
		staged = st->received - st->flushed;
		if (staged == sizeof(st->buf)) {
			err = ast_loader_stage_flush(st, sizeof(st->buf));
			if (err) {
				st->err = err;
				return err;
			}
			staged = 0;
		}

		copy = MIN(sizeof(st->buf) - staged, len);
		memcpy((uint8_t *)st->buf + staged, data, copy);
		st->received += copy;
		data += copy;
		len -= copy;
	}

	return 0;
}

static int _ast_loader_load_image_stream(uint32_t type, uint32_t *dst, uint32_t dst_check_max_len,
					 bool verify, uint32_t *img_read_size)
{
	struct ast_loader *loader = &g_loader;
	struct ast_loader_stage st;
	struct ast_loader_sink sink;
	uint32_t sz = 0;
	int err;

	if (!dst || !loader->load) {
		LOG_ERR("%s: Invalid input params", __func__);
		return -1;
	}

	LOG_INF("%s: type=%d, dst=0x%x, sec boot verify=%d",
		__func__, type, (uint32_t)dst, verify && cptra_manifest_sec_en());

	st.dst = dst;
	st.max_len = dst_check_max_len;
	st.type = type;
	st.verify = verify;
	st.hashing = false;
	st.last_ofst = UINT32_MAX;
	st.received = 0;
	st.flushed = 0;
	st.err = 0;

	sink.write = ast_loader_sink_write;
	sink.priv = &st;

	err = loader->load(loader, type, &sink, &sz);
	if (err || st.err) {
		err = err ? err : st.err;
		goto wipe;
	}

	if (sz == 0 && st.received == 0) {
		LOG_WRN("Img size == 0");
		if (img_read_size)
			*img_read_size = 0;
		return 0;
	}

	if (sz != st.received) {
		LOG_ERR("%s: size mismatch (reported=0x%x, received=0x%x)",
			__func__, sz, st.received);
		err = -1;
		goto wipe;
	}

	if (st.received - st.flushed) {
		err = ast_loader_stage_flush(&st, st.received - st.flushed);
		if (err)
			goto wipe;
	}

	err = ast_loader_verify_final(verify, type, dst);
	if (err) {
		LOG_ERR("%s: type %d verify failed, err=%d", __func__, type, err);
		goto wipe;
	}

	if (img_read_size)
		*img_read_size = sz;

	return 0;

wipe:
	/* destination held unverified data, scrub what was flushed to it */
	ast_loader_verify_abort();
	ast_loader_wipe(dst, st.flushed);
	return err;
}

static int _ast_loader_load(uint32_t type, uint32_t *dst, uint32_t dst_check_max_len,
			    bool verify, uint32_t *img_read_size)
{
	struct ast_loader *loader = &g_loader;

	if (loader->load_seg && loader->get_size)
		return _ast_loader_load_image_seg(type, dst, dst_check_max_len,
						  verify, img_read_size);

	return _ast_loader_load_image_stream(type, dst, dst_check_max_len,
					     verify, img_read_size);
}

/*
 * dst receives each chunk before verification completes, so every load must
 * be bounded by its destination. dst_check_max_len == 0 falls back to the
 * 64KB cap the old whole-image SRAM staging buffer imposed.
 */
int ast_loader_load_image(uint32_t type, uint32_t *dst, uint32_t dst_check_max_len, bool verify)
{
	if (dst_check_max_len == 0)
		dst_check_max_len = CONFIG_AST_LOADER_SRAM_MAX_SIZE;

	return _ast_loader_load(type, dst, dst_check_max_len, verify, NULL);
}

/*
 * Manifest images go to IME load addresses whose region sizes are unknown,
 * so stream them into the DRAM staging area at CONFIG_SYS_LOAD_ADDR first and
 * copy to dst only after verification passed: unverified data never reaches
 * dst and cannot spill into a neighbouring region.
 */
int ast_loader_load_manifest_image(uint32_t type, uint32_t *dst, bool verify, uint32_t *img_read_size)
{
	uint32_t *stage = (uint32_t *)CONFIG_SYS_LOAD_ADDR;
	uint32_t sz = 0;
	int err;

	if (!dst)
		return -1;

	err = _ast_loader_load(type, stage, CONFIG_AST_LOADER_DRAM_TEMP_BUF_MAX_SIZE,
			       verify, &sz);
	if (err)
		return err;

	if (sz)
		memcpy32(dst, stage, sz);

	if (img_read_size)
		*img_read_size = sz;

	return 0;
}

#if DT_NODE_HAS_STATUS(DT_NODELABEL(dma_pool), okay)
#define DMA_POOL_SECTION Z_GENERIC_SECTION(DMA_POOL)
#else
#define DMA_POOL_SECTION
#endif

uint8_t ast_loader_dma_pool[0x1000] DMA_POOL_SECTION;
static int ast_loader_probe(struct ast_chip *chip, struct ast_loader *loader)
{
	int err;

	loader->bootmode = chip->bootmode;
	loader->rev_id = sys_read32(SCU1_CHIP_REV_ID) & CHIP_ID_MASK;
	loader->dma_pool = ast_loader_dma_pool;

	LOG_DBG("%s: bootmode=%d\n", __func__, loader->bootmode);

	err = stor_init(loader);

	if (err == -1)
		err = recovery_init(loader);

	if (err) {
		LOG_ERR("Loader init failed %d.\n", err);
		return err;
	}

#if defined(CONFIG_CPTRA_MANIFEST_SIGNATURE) && defined(CONFIG_BOARD_AST2700_EVB_AST2700_A1_BOOTMCU)
	if (is_ast2700_a1()) {
		err = cptra_verify_abb_loader();
	}
#endif
	return err;
}

int ast_loader_init(struct ast_chip *chip)
{
	struct ast_loader *loader = &g_loader;
	int err;

	err = ast_loader_probe(chip, loader);

	return err;
}

int ast_loader_deinit(struct ast_chip *chip)
{
	struct ast_loader *loader = &g_loader;
	struct ast_loader_ops *ops;

	ops = ast_loader_get_ops(loader);
	if (ops && ops->deinit)
		return ops->deinit(loader);

	return 0;
}
