/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Notice, SPI driver operation should be moved to
 * driver layer after SPI driver is finished.
 * After that, normal Zephyr SPI driver should
 * be used.
 */

#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/logging/log.h>

#include <zephyr/drivers/flash.h>
#include <zephyr/drivers/spi_nor.h>
#include <zephyr/sys/util.h>
#include <abr.h>
#include <ast_loader.h>
#include <spi.h>

#define ASPEED_FMC_REG_BASE	0x14000000
#define ASPEED_SPI0_REG_BASE	0x14010000
#define ASPEED_SPI1_REG_BASE	0x14020000
#define INTR_CTRL		(ASPEED_FMC_REG_BASE + 0x008)
#define DRAM_HI_ADDR		(ASPEED_FMC_REG_BASE + 0x07C)
#define DMA_CTRL		(ASPEED_FMC_REG_BASE + 0x080)
#define DMA_FLASH_ADDR		(ASPEED_FMC_REG_BASE + 0x084)
#define DMA_RAM_ADDR		(ASPEED_FMC_REG_BASE + 0x088)
#define DMA_LEN			(ASPEED_FMC_REG_BASE + 0x08C)

#define SPI_DMA_MAX_LEN		0x02000000
#define SPI_DMA_DONE		0x00000800
#define DMA_ENABLE		0x00000001

#define MISC_CTRL_REG			0x54
#define   SPI_USER_CMD_MODE		BIT(27)
#define   SPI_CS_TO_DIS			BIT(26)
#define   SPI_UNALGNED_ACCESS		BIT(24)
#define   SPI_CS_CONTINUOUS		BIT(16)

LOG_MODULE_REGISTER(ast_spi, CONFIG_SOC_FMC_LOG_LEVEL);

/*
 * SCU flash size: SCU030[15:13]
 * 7: 512MB
 * 6: 256MB
 * 5: 128MB
 * 4: 64MB
 * 3: 32MB
 * 2: 16MB
 * 1: 8MB
 * 0: disabled
 */
static uint32_t spi_get_flash_sz_strap(void)
{
	uint32_t scu_flash_sz;
	uint32_t flash_sz_phy = SPI_SZ_256MB;

	scu_flash_sz = (sys_read32(SCU1_REG + 0x030) >> 13) & 0x7;
	switch (scu_flash_sz) {
	case 0x7:
		flash_sz_phy = SPI_SZ_512MB;
		break;
	case 0x6:
		flash_sz_phy = SPI_SZ_256MB;
		break;
	case 0x5:
		flash_sz_phy = SPI_SZ_128MB;
		break;
	case 0x4:
		flash_sz_phy = SPI_SZ_64MB;
		break;
	case 0x3:
		flash_sz_phy = SPI_SZ_32MB;
		break;
	case 0x2:
		flash_sz_phy = SPI_SZ_16MB;
		break;
	case 0x1:
		flash_sz_phy = SPI_SZ_8MB;
		break;
	case 0x0:
		flash_sz_phy = SPI_SZ_UNSET;
		break;
	default:
		flash_sz_phy = SPI_SZ_UNSET;
	}

	return flash_sz_phy;
}

static bool spi_single_flash_abr(void)
{
	return !!(sys_read32(SCU1_REG + 0x030) & BIT(29));
}

static int spi_copy(struct ast_loader *loader, uint32_t *dest, uint32_t src, uint32_t len)
{
	struct device *dev = loader->dev;
	int ret;

	if (!dev)
		return -1;

	if (abr_get_ind() &&
	    spi_single_flash_abr()) {
	    	LOG_DBG("single flash abr with size: 0x%x",
	    		spi_get_flash_sz_strap());
		src += spi_get_flash_sz_strap() / 2;
	}

	LOG_DBG("dest: %08x, src: %08x, len:%08x\n", (uint32_t)dest, src, len);
	ret = flash_read(dev, (off_t)src, (void *)dest, (size_t)len);
	if (ret) {
		LOG_ERR("fail to read flash fmc@0");
		return -1;
	}

        return 0;
}

static void hspi_init(void)
{
	uint32_t reg;

	reg = sys_read32(ASPEED_SPI0_REG_BASE + MISC_CTRL_REG);
	reg |= SPI_USER_CMD_MODE | SPI_UNALGNED_ACCESS;
	reg &= ~SPI_CS_CONTINUOUS;
	sys_write32(reg, ASPEED_SPI0_REG_BASE + MISC_CTRL_REG);

	reg = sys_read32(ASPEED_SPI1_REG_BASE + MISC_CTRL_REG);
	reg |= SPI_USER_CMD_MODE | SPI_UNALGNED_ACCESS;
	reg &= ~SPI_CS_CONTINUOUS;
	sys_write32(reg, ASPEED_SPI1_REG_BASE + MISC_CTRL_REG);
}

static int spi_init(struct ast_loader *loader)
{
	hspi_init();

        return 0;
}

static struct ast_loader_ops bootspi_ops = {
	.init = spi_init,
	.copy = spi_copy,
};

int spi_register(struct ast_loader *loader)
{
	struct device *dev;

	dev = (struct device *)device_get_binding("fmc@0");
	if (!dev) {
		LOG_ERR("No device named fmc@0");
		return -1;
	}

	loader->ops = &bootspi_ops;
	loader->dev = dev;

	LOG_DBG("SPI loader registered");

	return 0;
}
