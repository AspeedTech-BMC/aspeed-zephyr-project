// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
 */

#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/logging/log.h>
#include <fit.h>
#include <scu_ast2700.h>
#include <zephyr/sd/mmc.h>

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

LOG_MODULE_REGISTER(aspeed_mmc, CONFIG_SOC_FMC_LOG_LEVEL);

static const struct device *const sdhc_dev = DEVICE_DT_GET(DT_ALIAS(emmc));
static struct sd_card card;

int mmc_init(int id)
{
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

	ret = sd_init(sdhc_dev, &card);
	if (ret) {
		LOG_DBG("cannot get BLK driver\n");
		return -ENODEV;
	}

	ret = mmc_switch_part(&card, 1 << id);
	if (ret) {
		LOG_DBG("cannot switch part\n");
		return -1;
	}

	return ret;
}

int mmc_copy(uint32_t *dest, uint32_t src, uint32_t len)
{
	int ret;
	uint32_t blk, blks;
	uint32_t ofst_in_blk = src;
	uint32_t i = 0;
	uint32_t *base;

	blk = src / MMC_BLK_LEN;
	blks = len / MMC_BLK_LEN;
	ofst_in_blk %= MMC_BLK_LEN;

	if (len % MMC_BLK_LEN)
		blks++;

	if ((uint32_t)src % MMC_BLK_LEN)
		blks++;

	LOG_DBG("blk read blk=0x%x, blks=0x%x\n", blk, blks);

	ret = mmc_read_blocks(&card, (void *)ASPEED_SRAM_BASE, blk, blks);
	if (ret) {
		LOG_DBG("blk read is incomplete!!!\n");
		return 1;
	}

	base = (uint32_t *)(ASPEED_SRAM_BASE + ofst_in_blk);

	LOG_DBG("mmc load image base = %x\n", (uint32_t)base);
	LOG_DBG("mmc load image base[0] = %x\n", *base);

	for (i = 0; i < len / 4; i++)
		sys_write32(*(base + i), (uint32_t)(dest + i));

	if (len % MMC_BLK_LEN)
		sys_write32(*(base + i), (uint32_t)(dest + i));

	return 0;
}

uint32_t fit_mmc_load_read(struct fit_load_info *load, uint32_t sector,
			       uint32_t count, void *buf)
{
	int ret;

	LOG_DBG("%s: sector %x, count %x, buf %x",
	      __func__, sector, count, (uint32_t)buf);

	ret = mmc_read_blocks(&card, buf, sector, count);
	if (ret)
		return 0;

	return count;
}
