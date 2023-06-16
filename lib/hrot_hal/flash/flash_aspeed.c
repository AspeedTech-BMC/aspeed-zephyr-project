/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <drivers/flash.h>
#include <drivers/spi_nor.h>
#include <flash/flash_aspeed.h>
#include <kernel.h>
#include <sys/util.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr.h>
#include <flash_map.h>
#include <soc.h>

#define LOG_MODULE_NAME spi_api
#define NON_CACHED_SRAM_START      DT_REG_ADDR_BY_IDX(DT_NODELABEL(sram0), 1)
#define NON_CACHED_SRAM_SIZE       DT_REG_SIZE_BY_IDX(DT_NODELABEL(sram0), 1)
#define NON_CACHED_SRAM_END        (NON_CACHED_SRAM_START + NON_CACHED_SRAM_SIZE)

#include <logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME, LOG_LEVEL_DBG);

static char *Flash_Devices_List[6] = {
	"spi1_cs0",
	"spi1_cs1",
	"spi2_cs0",
	"spi2_cs1",
	"fmc_cs0",
	"fmc_cs1"
};

#if defined(CONFIG_SPI_DMA_SUPPORT_ASPEED)
static uint8_t flash_rw_buf[16384] NON_CACHED_BSS_ALIGN16;
#endif

static void Data_dump_buf(uint8_t *buf, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++) {
		printk("%02x ", buf[i]);
		if (i % 16 == 15)
			printk("\n");
	}
	printk("\n");
}

int BMC_PCH_SPI_Command(struct pspi_flash *flash, struct pflash_xfer *xfer)
{
	const struct device *flash_device;
	uint8_t DeviceId = flash->state->device_id[0];
	int AdrOffset = xfer->address;
	int Datalen = xfer->length;
	uint8_t *buf_addr = xfer->data;
	uint32_t FlashSize = 0;
	int ret = 0;
	int page_sz = 0;

	flash_device = device_get_binding(Flash_Devices_List[DeviceId]);
	if (!flash_device) {

		LOG_DBG("%s doesn't exist.\n", Flash_Devices_List[DeviceId]);
		return -1;
	}

#if defined(CONFIG_BMC_DUAL_FLASH)
	if (DeviceId == BMC_SPI) {
		FlashSize = flash_get_flash_size(flash_device);
		if (AdrOffset >= FlashSize) {
			DeviceId += 1;
			AdrOffset -= FlashSize;
			flash_device = device_get_binding(Flash_Devices_List[DeviceId]);
		}
	}
#endif

#if defined(CONFIG_CPU_DUAL_FLASH)
	if (DeviceId == PCH_SPI) {
		FlashSize = flash_get_flash_size(flash_device);
		if (AdrOffset >= FlashSize) {
			DeviceId += 1;
			AdrOffset -= FlashSize;
			flash_device = device_get_binding(Flash_Devices_List[DeviceId]);
		}
	}
#endif

	switch (xfer->cmd) {
	case SPI_APP_CMD_GET_FLASH_SIZE:
		if (!FlashSize)
			FlashSize = flash_get_flash_size(flash_device);
		return FlashSize;
	break;
#if 0
	case SPI_APP_CMD_GET_FLASH_SECTOR_SIZE:
		page_sz = flash_get_write_block_size(flash_device);
		return page_sz;
	break;
#else
	case MIDLEY_FLASH_CMD_WREN:
		ret = 0;	// bypass as write enabled
	break;
#endif
	case SPI_APP_CMD_GET_FLASH_BLOCK_SIZE:
		page_sz = spi_nor_get_erase_sz(flash_device, MIDLEY_FLASH_CMD_BLOCK_ERASE);
		return page_sz;
	break;
	case MIDLEY_FLASH_CMD_READ:
#if defined(CONFIG_SPI_DMA_SUPPORT_ASPEED)
	        if (buf_addr >= (uint8_t *)NON_CACHED_SRAM_START && buf_addr < (uint8_t *)NON_CACHED_SRAM_END) {
			ret = flash_read(flash_device, AdrOffset, xfer->data, Datalen);
		} else {
			ret = flash_read(flash_device, AdrOffset, flash_rw_buf, Datalen);
			memcpy(xfer->data, flash_rw_buf, Datalen);
		}
#else
		ret = flash_read(flash_device, AdrOffset, xfer->data, Datalen);
#endif
		//Data_dump_buf(buf,Datalen);
	break;
	case MIDLEY_FLASH_CMD_PP://Flash Write
#if defined(CONFIG_SPI_WRITE_DMA_SUPPORT_ASPEED)
	        if (buf_addr >= NON_CACHED_SRAM_START && buf_addr < NON_CACHED_SRAM_END) {
			ret = flash_write(flash_device, AdrOffset, xfer->data, Datalen);
		} else {
			memcpy(flash_rw_buf, xfer->data, Datalen);
			ret = flash_write(flash_device, AdrOffset, flash_rw_buf, Datalen);
		}
#else
		ret = flash_write(flash_device, AdrOffset, xfer->data, Datalen);
#endif
	break;
	case MIDLEY_FLASH_CMD_4K_ERASE:
		ret = spi_nor_erase_by_cmd(flash_device, AdrOffset, SECTOR_SIZE,
				MIDLEY_FLASH_CMD_4K_ERASE);
	break;
	case MIDLEY_FLASH_CMD_BLOCK_ERASE:
		ret = spi_nor_erase_by_cmd(flash_device, AdrOffset, BLOCK_SIZE,
				MIDLEY_FLASH_CMD_BLOCK_ERASE);
	break;
	case MIDLEY_FLASH_CMD_CE:
		FlashSize = flash_get_flash_size(flash_device);
		ret = flash_erase(flash_device, 0, FlashSize);
	break;
	case MIDLEY_FLASH_CMD_RDSR:
		// bypass as flash status are write enabled and not busy
		*xfer->data = 0x02;
		ret = 0;
	break;
	default:
		LOG_DBG("%d Command is not supported\n", xfer->cmd);
	break;
	}

	return ret;
}

int FMC_SPI_Command(struct pspi_flash *flash, struct pflash_xfer *xfer)
{
	const struct device *flash_device;
	const struct flash_area *partition_device;
	uint8_t *buf_addr = xfer->data;
	uint32_t FlashSize;
	int AdrOffset;
	int Datalen;
	int ret = 0;

	uint8_t DeviceId = flash->state->device_id[0];
	if (DeviceId <= ROT_INTERNAL_AFM)
		flash_device = device_get_binding(Flash_Devices_List[ROT_SPI]);
	else
		flash_device = device_get_binding(Flash_Devices_List[ROT_EXT_SPI]);

	AdrOffset = xfer->address;
	Datalen = xfer->length;

	switch (DeviceId) {
	case ROT_INTERNAL_ACTIVE:
		ret = flash_area_open(FLASH_AREA_ID(active), &partition_device);
		break;
	case ROT_INTERNAL_RECOVERY:
		ret = flash_area_open(FLASH_AREA_ID(recovery), &partition_device);
		break;
	case ROT_INTERNAL_STATE:
		ret = flash_area_open(FLASH_AREA_ID(state), &partition_device);
		break;
	case ROT_INTERNAL_INTEL_STATE:
		ret = flash_area_open(FLASH_AREA_ID(intel_state), &partition_device);
		break;
	case ROT_INTERNAL_KEY:
		ret = flash_area_open(FLASH_AREA_ID(key), &partition_device);
		break;
#if defined(CONFIG_BOOTLOADER_MCUBOOT)
	case ROT_INTERNAL_CERTIFICATE:
		ret = flash_area_open(FLASH_AREA_ID(certificate), &partition_device);
		break;
#endif
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	case ROT_INTERNAL_AFM:
		ret = flash_area_open(FLASH_AREA_ID(afm_act_1), &partition_device);
		break;
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	case ROT_EXT_CPLD_ACT:
		ret = flash_area_open(FLASH_AREA_ID(intel_cpld_act), &partition_device);
		break;
	case ROT_EXT_CPLD_RC:
		ret = flash_area_open(FLASH_AREA_ID(intel_cpld_rc), &partition_device);
		break;
#endif
	default:
		ret = -1;
		break;
	}

	if (ret) {
		LOG_ERR("Unknown partition");
		return ret;
	}

	switch (xfer->cmd) {
	case SPI_APP_CMD_GET_FLASH_SIZE:
		FlashSize = partition_device->fa_size;
		return FlashSize;
	break;
	case MIDLEY_FLASH_CMD_WREN:
		ret = 0;	// bypass as write enabled
	break;
	case MIDLEY_FLASH_CMD_READ:
#if defined(CONFIG_SPI_DMA_SUPPORT_ASPEED)
	        if (buf_addr >= (uint8_t *)NON_CACHED_SRAM_START && buf_addr < (uint8_t *)NON_CACHED_SRAM_END) {
			ret = flash_area_read(partition_device, AdrOffset, xfer->data, Datalen);
		} else {
			ret = flash_area_read(partition_device, AdrOffset, flash_rw_buf, Datalen);
			memcpy(xfer->data, flash_rw_buf, Datalen);
		}
#else
		ret = flash_area_read(partition_device, AdrOffset, xfer->data, Datalen);
#endif
	break;
	case MIDLEY_FLASH_CMD_PP://Flash Write
#if defined(CONFIG_SPI_DMA_WRITE_SUPPORT_ASPEED)
	        if (buf_addr >= NON_CACHED_SRAM_START && buf_addr < NON_CACHED_SRAM_END) {
			ret = flash_area_write(partition_device, AdrOffset, xfer->data, Datalen);
		} else {
			memcpy(flash_rw_buf, xfer->data, Datalen);
			ret = flash_area_write(partition_device, AdrOffset, flash_rw_buf, Datalen);
		}
#else
		ret = flash_area_write(partition_device, AdrOffset, xfer->data, Datalen);
#endif
	break;
	case MIDLEY_FLASH_CMD_4K_ERASE:
		ret = spi_nor_erase_by_cmd(flash_device, partition_device->fa_off + AdrOffset,
				SECTOR_SIZE, MIDLEY_FLASH_CMD_4K_ERASE);
	break;
	case MIDLEY_FLASH_CMD_BLOCK_ERASE:
		ret = spi_nor_erase_by_cmd(flash_device, partition_device->fa_off + AdrOffset,
				BLOCK_SIZE, MIDLEY_FLASH_CMD_BLOCK_ERASE);
	break;
	case MIDLEY_FLASH_CMD_CE:
		LOG_DBG("%d Command is not supported\n", xfer->cmd);
		ret = 0;
	break;
	case MIDLEY_FLASH_CMD_RDSR:
		// bypass as flash status are write enabled and not busy
		*xfer->data = 0x02;
		ret = 0;
	break;
	default:
		LOG_ERR("%d Command is not supported\n", xfer->cmd);
	break;
	}

	return ret;
}

int SPI_Command_Xfer(struct pspi_flash *flash, struct pflash_xfer *xfer)
{
	uint8_t DeviceId = flash->state->device_id[0];
	int ret  = 0;

	if (DeviceId <= PCH_SPI)
		ret = BMC_PCH_SPI_Command(flash, xfer);
	else
		ret = FMC_SPI_Command(flash, xfer);
	return ret;
}

