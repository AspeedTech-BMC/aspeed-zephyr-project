/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * Flash read/write for SoCs whose SPI DMA only reaches RAM_NC (AST1060):
 * caller buffers outside RAM_NC bounce through a 16 KB RAM_NC buffer.
 */

#include <zephyr/drivers/flash.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <string.h>
#include <zephyr/storage/flash_map.h>
#include <soc.h>
#include <flash/flash_aspeed.h>

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(spi_api, LOG_LEVEL_DBG);

#define NON_CACHED_SRAM_START      DT_REG_ADDR(DT_NODELABEL(sram1))
#define NON_CACHED_SRAM_SIZE       DT_REG_SIZE(DT_NODELABEL(sram1))
#define NON_CACHED_SRAM_END        (NON_CACHED_SRAM_START + NON_CACHED_SRAM_SIZE)

#if defined(CONFIG_SPI_DMA_SUPPORT_ASPEED) || defined(CONFIG_SPI_WRITE_DMA_SUPPORT_ASPEED)
struct k_mutex flash_rw_mutex;
static bool mutex_init = false;
static uint8_t flash_rw_buf[16384] NON_CACHED_BSS_ALIGN16;
#endif

#if defined(CONFIG_SPI_DMA_SUPPORT_ASPEED) || defined(CONFIG_SPI_WRITE_DMA_SUPPORT_ASPEED)
void init_flash_rw_buf_mutex(void)
{
	if (!mutex_init) {
		k_mutex_init(&flash_rw_mutex);
		mutex_init = true;
	}
}
#endif

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

#if defined(CONFIG_SPI_DMA_SUPPORT_ASPEED)
	if (data >= (uint8_t *)NON_CACHED_SRAM_START && data < (uint8_t *)NON_CACHED_SRAM_END) {
		ret = flash_read(flash_dev, address, data, data_length);
	} else {
		if (k_mutex_lock(&flash_rw_mutex, K_MSEC(1000)))
			return -1;
		ret = flash_read(flash_dev, address, flash_rw_buf, data_length);
		memcpy(data, flash_rw_buf, data_length);
		k_mutex_unlock(&flash_rw_mutex);
	}
#else
	ret = flash_read(flash_dev, address, data, data_length);
#endif

	return ret;
}

int rot_flash_read(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	int ret = 0;
	const struct flash_area *fa;

	ret = get_rot_region(device_id, &fa);
	if (ret)
		return ret;

	if (address + data_length > fa->fa_size) {
		LOG_ERR("Address out of range, address=0x%x, length=0x%x", address, data_length);
		return -1;
	}

#if defined(CONFIG_SPI_DMA_SUPPORT_ASPEED)
	if (data >= (uint8_t *)NON_CACHED_SRAM_START && data < (uint8_t *)NON_CACHED_SRAM_END) {
		ret = flash_area_read(fa, address, data, data_length);
	} else {
		if (k_mutex_lock(&flash_rw_mutex, K_MSEC(1000)))
			return -1;
		ret = flash_area_read(fa, address, flash_rw_buf, data_length);
		memcpy(data, flash_rw_buf, data_length);
		k_mutex_unlock(&flash_rw_mutex);
	}
#else
	ret = flash_area_read(fa, address, data, data_length);
#endif

	return ret;
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

#if defined(CONFIG_SPI_DMA_WRITE_SUPPORT_ASPEED)
	if (data >= (uint8_t *)NON_CACHED_SRAM_START && data < (uint8_t *)NON_CACHED_SRAM_END) {
		ret = flash_write(flash_dev, address, data, data_length);
	} else {
		if (k_mutex_lock(&flash_rw_mutex, K_MSEC(1000)))
			return -1;
		ret = flash_write(flash_dev, address, flash_rw_buf, data_length);
		memcpy(data, flash_rw_buf, data_length);
		k_mutex_unlock(&flash_rw_mutex);
	}
#else
	ret = flash_write(flash_dev, address, data, data_length);
#endif

	return ret;
}

int rot_flash_write(uint8_t device_id, uint32_t address, uint32_t data_length, uint8_t *data)
{
	int ret = 0;
	const struct flash_area *fa;

	ret = get_rot_region(device_id, &fa);
	if (ret)
		return ret;

	if (address + data_length > fa->fa_size) {
		LOG_ERR("Address out of range, address=0x%x, length=0x%x", address, data_length);
		return -1;
	}

#if defined(CONFIG_SPI_DMA_WRITE_SUPPORT_ASPEED)
	if (data >= (uint8_t *)NON_CACHED_SRAM_START && data < (uint8_t *)NON_CACHED_SRAM_END) {
		ret = flash_area_write(fa, address, data, data_length);
	} else {
		if (k_mutex_lock(&flash_rw_mutex, K_MSEC(1000)))
			return -1;
		ret = flash_area_write(fa, address, flash_rw_buf, data_length);
		memcpy(data, flash_rw_buf, data_length);
		k_mutex_unlock(&flash_rw_mutex);
	}
#else
	ret = flash_area_write(fa, address, data, data_length);
#endif

	return ret;
}
