/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/sys_io.h>

#include <psp/abr.h>

LOG_MODULE_REGISTER(abr, LOG_LEVEL_INF);

#define WDT_ABR_CTRL		0x4c
#define WDT_ABR_INDICATOR	BIT(1)

#define SPI_SZ_UNSET		0x0
#define SPI_SZ_8MB		0x800000
#define SPI_SZ_16MB		0x1000000
#define SPI_SZ_32MB		0x2000000
#define SPI_SZ_64MB		0x4000000
#define SPI_SZ_128MB		0x8000000
#define SPI_SZ_256MB		0x10000000
#define SPI_SZ_512MB		0x20000000

bool abr_enabled(void)
{
	return (sys_read32(ABR_REG) & ABR_EN);
}

uint32_t abr_get_ind(void)
{
	uint32_t val;

	val = !!(sys_read32(WDTA_REG + WDT_ABR_CTRL) & WDT_ABR_INDICATOR);

	return val;
}

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

	scu_flash_sz = (sys_read32(ABR_REG) >> 13) & 0x7;
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
	return !!(sys_read32(ABR_REG) & ABR_MODE);
}

int abr_get_flash_offset(uint32_t *offset)
{
	uint32_t flash_sz;

	*offset = 0;

	if (!abr_get_ind() || !spi_single_flash_abr()) {
		return 0;
	}

	flash_sz = spi_get_flash_sz_strap();
	if (flash_sz == SPI_SZ_UNSET) {
		LOG_ERR("ABR indicator is set but the flash size strap is unset");
		return -EINVAL;
	}

	*offset = flash_sz / 2;
	LOG_DBG("single flash abr with size: 0x%x", flash_sz);

	return 0;
}

int abr_flash_read(const struct device *dev, off_t offset, void *data, size_t len)
{
	uint32_t abr_offset;
	int ret;

	ret = abr_get_flash_offset(&abr_offset);
	if (ret) {
		return ret;
	}

	return flash_read(dev, offset + abr_offset, data, len);
}
