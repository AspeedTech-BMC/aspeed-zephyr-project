/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * Flash read/write for AST1080: the AST10x0-G2 SPI driver keeps DMA buffers
 * cache-coherent itself and falls back to PIO for buffers it cannot DMA, so
 * caller buffers (including the IO SRAM sram_buf) go straight to the driver
 * instead of bouncing through a RAM_NC buffer as on AST1060.
 */

#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <flash/flash_aspeed.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(spi_api, LOG_LEVEL_DBG);

/* Nothing to guard: there is no shared bounce buffer. */
void init_flash_rw_buf_mutex(void)
{
}

int bmc_pch_flash_read(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	const struct device *flash_dev;
	int ret;

	ret = get_flash_dev(device_id, &address, &flash_dev);
	if (ret)
		return ret;

	if (address + data_length > flash_get_flash_size(flash_dev)) {
		LOG_ERR("Address out of range, address=0x%x, length=0x%x", address, data_length);
		return -1;
	}

	return flash_read(flash_dev, address, data, data_length);
}

int rot_flash_read(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	const struct flash_area *fa;
	int ret;

	ret = get_rot_region(device_id, &fa);
	if (ret)
		return ret;

	if (address + data_length > fa->fa_size) {
		LOG_ERR("Address out of range, address=0x%x, length=0x%x", address, data_length);
		return -1;
	}

	return flash_area_read(fa, address, data, data_length);
}

int bmc_pch_flash_write(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	const struct device *flash_dev;
	int ret;

	ret = get_flash_dev(device_id, &address, &flash_dev);
	if (ret)
		return ret;

	if (address + data_length > flash_get_flash_size(flash_dev)) {
		LOG_ERR("Address out of range, address=0x%x, length=0x%x", address, data_length);
		return -1;
	}

	return flash_write(flash_dev, address, data, data_length);
}

int rot_flash_write(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	const struct flash_area *fa;
	int ret;

	ret = get_rot_region(device_id, &fa);
	if (ret)
		return ret;

	if (address + data_length > fa->fa_size) {
		LOG_ERR("Address out of range, address=0x%x, length=0x%x", address, data_length);
		return -1;
	}

	return flash_area_write(fa, address, data, data_length);
}
