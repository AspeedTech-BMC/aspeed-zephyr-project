// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) ASPEED Technology Inc.
 */

#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/logging/log.h>
#include <scu_ast2700.h>
#include <ast_loader.h>
#include <chip.h>

LOG_MODULE_REGISTER(ast_loader, CONFIG_SOC_FMC_LOG_LEVEL);

#define AST_HASH_BUFFER            0x14baf800
struct ast_loader g_loader;

static int ast_loader_verify(uint32_t type, uint32_t *message, uint32_t len)
{
//	struct fmc_hdr_v2 *hdr = (struct fmc_hdr_v2 *)(_start - sizeof(struct fmc_hdr_v2));
//	struct image_region region[1];
//	u8 hash[HDR_DGST_LEN];
//	int err;
//
//	region[0].data = message;
//	region[0].size = len;
//
//	err = hash_calculate("sha384", region, 1, hash);
//	if (err) {
//		printf("%s Hash calculate err=%d\n", __func__, err);
//		return err;
//	}
//
//	printf("0x%x\n", *((uint32_t *)hash));
//	err = memcmp(hash, hdr->body.pbs[type - 1].dgst, sizeof(hash));
//
//	return err;
return 0;
}

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
		err = ops->copy(loader->dev, dst, src, len);
		if (err)
			return err;
	}

	return err;
}

int ast_loader_load_image(uint32_t type, uint32_t *dst, bool verify)
{
	struct ast_loader *loader = &g_loader;
	uint32_t *hash_buf = (uint32_t *)AST_HASH_BUFFER;
	uint32_t sz = 0;
	int err = 0;

	if (loader->load) {
		err = loader->load(loader, type, hash_buf, &sz);
		if (err)
			return err;
	}

	if (loader->verify && verify) {
		if (!hash_buf || sz == 0) {
			LOG_ERR("Hash buffer is NULL or size is zero.\n");
			return -1;
		}

		err = loader->verify(type, hash_buf, sz);
		if (err) {
			printf("%s: verify failed, err=%d\n", __func__, err);
			return err;
		}
	}

	memcpy32(dst, hash_buf, sz);

	return err;
}

static int ast_loader_probe(struct ast_chip *chip, struct ast_loader *loader)
{
	int err;

	loader->bootmode = chip->bootmode;

	LOG_DBG("%s: bootmode=%d\n", __func__, loader->bootmode);

	err = stor_init(loader);
	if (err == -1)
		err = recovery_init(loader);

	if (err)
		return err;

	loader->rev_id = sys_read32(SCU1_CHIP_REV_ID) & CHIP_ID_MASK;
	loader->verify = ast_loader_verify;

	return err;
}

int ast_loader_init(struct ast_chip *chip)
{
	struct ast_loader *loader = &g_loader;
	int err;

	err = ast_loader_probe(chip, loader);

	return err;
}
