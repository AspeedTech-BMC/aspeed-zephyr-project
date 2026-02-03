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

LOG_MODULE_REGISTER(ast_mmc, CONFIG_SDHC_LOG_LEVEL);

static struct sd_card card;

static int mmc_init(struct device *dev)
{
	int ret = 0;

	if (is_ast2700_a1()) {
		/* set clk/cmd driving */
		sys_write32(2, MMC_CLK_DRIVING_REG);
		sys_write32(1, MMC_CMD_DRIVING_REG);
		sys_write32(1, MMC_DAT0_DRIVING_REG);
		sys_write32(1, MMC_DAT1_DRIVING_REG);
		sys_write32(1, MMC_DAT2_DRIVING_REG);
		sys_write32(1, MMC_DAT3_DRIVING_REG);
	} else if (is_ast2700_a2()) {
		sys_write32(3, MMC_CLK_DRIVING_REG);
		sys_write32(1, MMC_CMD_DRIVING_REG);
		sys_write32(1, MMC_DAT0_DRIVING_REG);
		sys_write32(1, MMC_DAT1_DRIVING_REG);
		sys_write32(1, MMC_DAT2_DRIVING_REG);
		sys_write32(1, MMC_DAT3_DRIVING_REG);
	}

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

static int mmc_copy(struct device *dev, uint32_t *dst, uint32_t src, uint32_t len)
{
	int ret;
	uint32_t *base;
	uint32_t blks;
	uint32_t offset, lba, trans, extra;
	uint8_t blk_buf[MMC_BLK_LEN], *out = (uint8_t *)dst, *in = (uint8_t *)src;

	lba = (uint32_t)src / MMC_BLK_LEN;
	offset = (uint32_t)src % MMC_BLK_LEN;

	/* Handle the case where the source address is not aligned to block size */
	if (offset) {
		if (len < (MMC_BLK_LEN - offset))
			trans = len;
		else
			trans = MMC_BLK_LEN - offset;

		/* Read the first block to get the offset */
		ret = mmc_read_blocks(&card, (void *)blk_buf, lba, 1);
		if (ret) {// != 1) {
			LOG_ERR("blk read is incomplete!!!\n");
			return -1;
		}

		base = (uint32_t *)(blk_buf + offset);
		memcpy(dst, base, trans);

		out += trans;
		in  += trans;
		len -= trans;
	}

	/* Read the rest of the blocks */
	while (len)  {
		blks = len / MMC_BLK_LEN;
		extra = len % MMC_BLK_LEN;

		lba = (uint32_t)in / MMC_BLK_LEN;
		offset = (uint32_t)in % MMC_BLK_LEN;

		if (len == extra) {
			/* Read out the last block */
			ret = mmc_read_blocks(&card, (void *)blk_buf, lba, 1);
			if (ret) {// != 1) {
				LOG_ERR("blk read is incomplete!!!\n");
				return -1;
			}

			memcpy(out, blk_buf + offset, extra);

			out += extra;
			in += extra;
			len -= extra;
		} else {
			/* Read out the whole block */
			ret = mmc_read_blocks(&card, (void *)out, lba, blks);
			LOG_DBG("blk read cnt=%d\n", ret);
			if (ret) {// != blks) {
				LOG_ERR("blk read is incomplete!!!\n");
				return -1;
			}

			out += (MMC_BLK_LEN * blks);
			in += (MMC_BLK_LEN * blks);
			len -= (MMC_BLK_LEN * blks);
		}
	}

	return ret;
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
