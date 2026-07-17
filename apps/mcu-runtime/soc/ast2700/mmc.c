/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/logging/log.h>
#include <scu.h>
#include <zephyr/sd/mmc.h>
#include <ast_loader.h>
#include <abr.h>

#define MMC_CLK_DRIVING_REG	(SCU0_REG + 0x480)
#define MMC_CMD_DRIVING_REG	(SCU0_REG + 0x484)
#define MMC_DAT0_DRIVING_REG	(SCU0_REG + 0x488)
#define MMC_DAT1_DRIVING_REG	(SCU0_REG + 0x48c)
#define MMC_DAT2_DRIVING_REG	(SCU0_REG + 0x490)
#define MMC_DAT3_DRIVING_REG	(SCU0_REG + 0x494)
#define MMC_CD_DRIVING_REG	(SCU0_REG + 0x498)
#define MMC_WP_DRIVING_REG	(SCU0_REG + 0x49c)
#define MMC_DAT4_DRIVING_REG	(SCU0_REG + 0x4a0)
#define MMC_DAT5_DRIVING_REG	(SCU0_REG + 0x4a4)
#define MMC_DAT6_DRIVING_REG	(SCU0_REG + 0x4a8)
#define MMC_DAT7_DRIVING_REG	(SCU0_REG + 0x4ac)

#define MMC_BLK_LEN	512
#define MMC_DMA_POOL_LEN	0x1000

LOG_MODULE_REGISTER(ast_mmc, CONFIG_SDHC_LOG_LEVEL);

static struct sd_card card;

static int mmc_init(struct ast_loader *loader)
{
	struct device *dev = loader->dev;
	int ret = 0;

	/* set clk/cmd driving */
	sys_write32(2, MMC_CLK_DRIVING_REG);
	sys_write32(1, MMC_CMD_DRIVING_REG);
	sys_write32(1, MMC_DAT0_DRIVING_REG);
	sys_write32(1, MMC_DAT1_DRIVING_REG);
	sys_write32(1, MMC_DAT2_DRIVING_REG);
	sys_write32(1, MMC_DAT3_DRIVING_REG);

	/* release emmc pin from emmc boot */
	sys_write32(0, 0x12c0b00c);

	/* config gpio18 a0 to A5 to emmc mode */
	sys_write32(0xff, 0x12c02400);

	ret = sd_init(dev, &card);
	if (ret) {
		LOG_ERR("cannot get BLK driver\n");
		return -ENODEV;
	}

	ret = mmc_switch_part(&card, 1 << abr_get_ind());
	if (ret) {
		LOG_ERR("cannot switch part\n");
		return -1;
	}

	return ret;
}

static int mmc_copy(struct ast_loader *loader, uint32_t *dst, uint32_t src, uint32_t len)
{
	int ret;
	uint32_t blks;
	uint32_t offset, lba, trans;
	uint8_t *blk_buf = loader->dma_pool, *out = (uint8_t *)dst;

	/*
	 * Always DMA into the dma_pool bounce buffer and copy out from
	 * there: dst may live in memory the MMC DMA master has no write
	 * permission to (GSRAM sprot only opens the pool).
	 */
	while (len) {
		lba = src / MMC_BLK_LEN;
		offset = src % MMC_BLK_LEN;
		trans = MIN(len, MMC_DMA_POOL_LEN - offset);
		blks = DIV_ROUND_UP(offset + trans, MMC_BLK_LEN);

		ret = mmc_read_blocks(&card, (void *)blk_buf, lba, blks);
		if (ret) {
			LOG_ERR("blk read is incomplete!!!\n");
			return -1;
		}

		memcpy(out, blk_buf + offset, trans);

		out += trans;
		src += trans;
		len -= trans;
	}

	return 0;
}

static struct ast_loader_ops bootmmc_ops = {
	.init = mmc_init,
	.copy = mmc_copy,
};

int mmc_register(struct ast_loader *loader)
{
	struct device *dev;

	dev = (struct device *)device_get_binding("sdhci@12090000");
	if (!dev) {
		LOG_ERR("No device named emmc");
		return -1;
	}

	loader->ops = &bootmmc_ops;
	loader->dev = dev;

	LOG_DBG("MMC loader registered");

	return 0;
}
