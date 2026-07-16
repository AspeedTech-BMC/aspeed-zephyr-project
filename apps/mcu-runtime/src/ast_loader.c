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
#include <zephyr/logging/log.h>
#include <scu.h>
#include <ast_loader.h>
#include <chip.h>

LOG_MODULE_REGISTER(ast_loader, CONFIG_SOC_FMC_LOG_LEVEL);

struct ast_loader g_loader;

#ifdef CONFIG_CPTRA_MANIFEST_SIGNATURE
static int ast_loader_verify(uint32_t type, uint32_t *message, uint32_t len, uint32_t buf_len)
{
	int err = 0;

	if (type != CPTRA_MANIFEST_FW_ID) {
		err = cptra_verify_image((uint8_t *)message, len, type);
	} else {

#ifndef CONFIG_CPTRA_2X_LAYOUT
		err = cptra_verify_soc_manifest(
			(struct cptra_soc_manifest_verify_buf *)message, buf_len);
		if (err)
			goto end;

		err = cptra_verify_soc_manifest_ver(
			(struct cptra_soc_manifest *)message);
#endif
	}

end:
	return err;
}
#endif

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

static int _ast_loader_load_image(uint32_t type, uint32_t *dst, uint32_t dst_check_max_len, uint32_t *buf, uint32_t buf_size,
								  bool verify, uint32_t *img_read_size)
{
	struct ast_loader *loader = &g_loader;
	uint32_t sz = 0;
	int err;

	if (!dst || !buf || buf_size == 0 || !loader->load) {
		LOG_ERR("%s: Invalid input params", __func__);
		return -1;
	}

	LOG_INF("%s: type=%d, dst=0x%x, buf=0x%x, sec boot verify=%d",
		__func__, type, (uint32_t)dst, (uint32_t)buf, verify && cptra_manifest_sec_en());

	err = loader->load(loader, type, buf, &sz);
	if (err)
		return err;

	if (sz == 0) {
		LOG_WRN("Img size == 0");
		if (img_read_size)
			*img_read_size = 0;
		return 0;
	}

	if (sz > buf_size || (dst_check_max_len != 0 && sz > dst_check_max_len)) {
		LOG_ERR("Img size (0x%x) exceeds tmp buf size (0x%x) or dst buf size (0x%x)", sz, buf_size, dst_check_max_len);
		return -1;
	}

	if (verify) {
		if (!loader->verify) {
			LOG_ERR("Verifier does not be registered.");
			return -1;
		}

		err = loader->verify(type, buf, sz, buf_size);
		if (err) {
			LOG_ERR("%s: type %d verify failed, err=%d", __func__, type, err);
			return err;
		}
	}

	// make sure verify pass before copy to destination
	if (img_read_size)
		*img_read_size = sz;
	memcpy32(dst, buf, sz);

	return 0;
}

int ast_loader_load_image(uint32_t type, uint32_t *dst, uint32_t dst_check_max_len, bool verify)
{
	uint8_t temp_buf[CONFIG_AST_LOADER_TEMP_BUF_SIZE];

	return _ast_loader_load_image(type, dst, dst_check_max_len,
				      (uint32_t *)temp_buf,
				      CONFIG_AST_LOADER_TEMP_BUF_SIZE, verify, NULL);
}

int ast_loader_load_manifest_image(uint32_t type, uint32_t *dst, bool verify, uint32_t *img_read_size)
{
	return _ast_loader_load_image(type, dst, 0, (uint32_t *)CONFIG_SYS_LOAD_ADDR,
								  CONFIG_AST_LOADER_DRAM_TEMP_BUF_MAX_SIZE, verify, img_read_size);
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

#ifdef CONFIG_CPTRA_MANIFEST_SIGNATURE
	LOG_INF("Registering manifest verifier...\n");
	loader->verify = ast_loader_verify;
#endif

#ifdef CONFIG_CPTRA_MANIFEST_SIGNATURE
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
