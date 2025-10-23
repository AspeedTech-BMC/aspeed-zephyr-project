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

#define AST_HASH_BUFFER            0x14baf800
struct ast_loader g_loader;

#ifdef CONFIG_CPTRA_MANIFEST_SIGNATURE
static int ast_loader_verify(uint32_t type, uint32_t *message, uint32_t len)
{
	int err = 0;

	if (type != CPTRA_MANIFEST_FW_ID) {
		err = cptra_verify_image((uint8_t *)message, len, type);
	} else {
		err = cptra_verify_soc_manifest(
			(struct cptra_soc_manifest *)message);
		if (err)
			goto end;

		err = cptra_verify_soc_manifest_ver(
			(struct cptra_soc_manifest *)message);
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
		err = ops->copy(loader->dev, dst, src, len);
		if (err)
			return err;
	}

	return err;
}

static int _ast_loader_load_image(uint32_t type, uint32_t *dst, uint32_t *buf, bool verify)
{
	struct ast_loader *loader = &g_loader;
	uint32_t sz = 0;
	int err = 0;
	LOG_INF("%s: type=%d, dst=0x%x, buf=0x%x, verify=%d\n",
		__func__, type, (uint32_t)dst, (uint32_t)buf, verify);

	if (loader->load) {
		err = loader->load(loader, type, buf, &sz);
		if (err)
			return err;
	}

	if (verify) {
		if (!loader->verify) {
			LOG_ERR("Verifier does not be registered.\n");
			return -1;
		}

		if (!buf || sz == 0) {
			LOG_ERR("Hash buffer is NULL or size is zero.\n");
			return -1;
		}

		err = loader->verify(type, buf, sz);
		if (err) {
			printf("%s: type %d verify failed, err=%d\n", __func__, type, err);
			return err;
		}
	}

	memcpy32(dst, buf, sz);

	return err;
}

int ast_loader_load_image(uint32_t type, uint32_t *dst, bool verify)
{
	return _ast_loader_load_image(type, dst, (uint32_t *)AST_HASH_BUFFER, 1);
}

int ast_loader_load_manifest_image(uint32_t type, uint32_t *dst, bool verify)
{
	return _ast_loader_load_image(type, dst, (uint32_t *)CONFIG_SYS_LOAD_ADDR, 1);
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
#ifdef CONFIG_CPTRA_MANIFEST_SIGNATURE
	loader->verify = ast_loader_verify;
#endif

#ifdef CONFIG_CPTRA_MANIFEST_SIGNATURE
	err = cptra_verify_abb_loader();
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
