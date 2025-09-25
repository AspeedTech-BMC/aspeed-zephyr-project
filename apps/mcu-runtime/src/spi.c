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
#include <ast_loader.h>

#define ASPEED_FMC_REG_BASE	0x14000000
#define INTR_CTRL		(ASPEED_FMC_REG_BASE + 0x008)
#define DRAM_HI_ADDR		(ASPEED_FMC_REG_BASE + 0x07C)
#define DMA_CTRL		(ASPEED_FMC_REG_BASE + 0x080)
#define DMA_FLASH_ADDR		(ASPEED_FMC_REG_BASE + 0x084)
#define DMA_RAM_ADDR		(ASPEED_FMC_REG_BASE + 0x088)
#define DMA_LEN			(ASPEED_FMC_REG_BASE + 0x08C)

#define SPI_DMA_MAX_LEN		0x02000000
#define SPI_DMA_DONE		0x00000800
#define DMA_ENABLE		0x00000001

#define ASPEED_IO_FWSPI_DRIVING         (SCU1_REG + 0x4E0)
#define ASPEED_IO_SPI0_DRIVING          (SCU1_REG + 0x4CC)
#define ASPEED_IO_SPI1_DRIVING          (SCU1_REG + 0x4CC)
#define ASPEED_IO_SPI2_DRIVING          (SCU1_REG + 0x4D0)

LOG_MODULE_REGISTER(ast_spi, CONFIG_SOC_FMC_LOG_LEVEL);

//static void aspeed_memmove_spi_dma_op(void *dest, const void *src, uint32_t count)
//{
//	uint32_t dma_busy = 0;
//
//	if (dest == src)
//		return;
//
//	if ((uint32_t)dest % 4 != 0 || (uint32_t)src % 4 != 0) {
//		memcpy(dest, src, count);
//		return;
//	}
//
//	if ((uint32_t)src >= ASPEED_FMC_CS0_BASE &&
//	    (uint32_t)src < (ASPEED_FMC_CS0_BASE + ASPEED_FMC_CS0_SIZE) &&
//	    (uint32_t)dest >= ASPEED_DRAM_BASE) {
//
//		*((volatile uint32_t *)DRAM_HI_ADDR) = 0x4;
//
//		*((volatile uint32_t *)DMA_RAM_ADDR) = (uint32_t)dest - ASPEED_DRAM_BASE;
//		*((volatile uint32_t *)DMA_FLASH_ADDR) = (uint32_t)src - ASPEED_FMC_CS0_BASE;
//		*((volatile uint32_t *)DMA_LEN) = (uint32_t)count - 1;
//		*((volatile uint32_t *)DMA_CTRL) = (uint32_t)DMA_ENABLE;
//
//		do {
//			dma_busy = (*((volatile uint32_t *)INTR_CTRL)) & SPI_DMA_DONE;
//		} while (dma_busy == 0);
//
//		*((volatile uint32_t *)DMA_CTRL) = 0x0;
//	} else {
//		memcpy(dest, src, count);
//	}
//}
//
//uint32_t fit_ram_load_read(struct fit_load_info *load, uint32_t sector,
//			       uint32_t count, void *buf)
//{
//	uint32_t addr;
//
//	LOG_DBG("%s: sector %x, count %x, buf %x",
//	      __func__, sector, count, (uint32_t)buf);
//
//	addr = CONFIG_SOC_FMC_LOAD_FIT_ADDRESS + sector;// + aspeed_spi_abr_offset();
////	  if (CONFIG_IS_ENABLED(IMAGE_PRE_LOAD))
////		  addr += image_load_offset;
//
//	aspeed_memmove_spi_dma_op(buf, (void *)addr, count);
//
//	return count;
//}

static int spi_copy(struct device *dev, uint32_t *dest, uint32_t src, uint32_t len)
{
	int ret;

	if (!dev)
		return -1;

	LOG_DBG("dest: %08x, src: %08x, len:%08x\n", (uint32_t)dest, src, len);
	ret = flash_read(dev, (off_t)src, (void *)dest, (size_t)len);
	if (ret) {
		LOG_ERR("fail to read flash fmc@0");
		return -1;
	}

        return 0;
}

void spi_adjust_driving_strength(void)
{
	uint32_t reg;

	/* FMC driving strength: SCUIO_4E0[15:0] */
	reg = readl((void *)ASPEED_IO_FWSPI_DRIVING);
	reg &= ~(0x0000ffff);
	reg |= 0x0000aaaa;
	writel(reg, (void *)ASPEED_IO_FWSPI_DRIVING);

	/* SPI0 driving strength: SCUIO_4CC[11:0] */
	reg = readl((void *)ASPEED_IO_SPI0_DRIVING);
	reg &= ~(0x00000fff);
	reg |= 0x00000aaa;
	writel(reg, (void *)ASPEED_IO_SPI0_DRIVING);

	/* SPI1 driving strength: SCUIO_4CC[27:16] */
	reg = readl((void *)ASPEED_IO_SPI1_DRIVING);
	reg &= ~(0x0fff0000);
	reg |= 0x0aaa0000;
	writel(reg, (void *)ASPEED_IO_SPI1_DRIVING);

	/* SPI2 driving strength: SCUIO_4D0[15:0] */
	reg = readl((void *)ASPEED_IO_SPI2_DRIVING);
	reg &= ~(0x0000ffff);
	reg |= 0x00002aaa;
	writel(reg, (void *)ASPEED_IO_SPI2_DRIVING);
}

static int spi_init(struct device *dev)
{
	spi_adjust_driving_strength();

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
