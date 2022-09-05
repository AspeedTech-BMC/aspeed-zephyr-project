/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_CERBERUS_PFR)

#include <stdint.h>
#include <logging/log.h>
#include "cerberus_pfr_common.h"
#include "manifest/pfm/pfm_format.h"
#include "manifest/manifest_format.h"
#include "pfr/pfr_util.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

uint32_t cerberus_get_rw_region_addr(int spi_dev, uint32_t pfm_addr, uint16_t *region_cnt)
{
	uint32_t read_address;

	// Get read only regions from PFM
	read_address = pfm_addr + sizeof(struct manifest_header);

	// Get region counts
	struct manifest_toc_header toc_header;
	if (pfr_spi_read(spi_dev, read_address, sizeof(toc_header),
				(uint8_t*)&toc_header)) {
		LOG_ERR("Failed to read toc header");
		return 0;
	}
	read_address += sizeof(toc_header) +
		(toc_header.entry_count * sizeof(struct manifest_toc_entry)) +
		(toc_header.entry_count * SHA256_HASH_LENGTH) +
		SHA256_HASH_LENGTH;

	// Platform Header Offset
	struct manifest_platform_id plat_id_header;

	if (pfr_spi_read(spi_dev, read_address, sizeof(plat_id_header),
				(uint8_t *)&plat_id_header)) {
		LOG_ERR("Failed to read TOC header");
		return 0;
	}

	// id length should be 4 byte aligned
	uint8_t alignment = (plat_id_header.id_length % 4) ?
		(4 - (plat_id_header.id_length % 4)) : 0;
	uint16_t id_length = plat_id_header.id_length + alignment;
	read_address += sizeof(plat_id_header) + id_length;

	// Flash Device Element Offset
	struct pfm_flash_device_element flash_dev;

	if (pfr_spi_read(spi_dev, read_address, sizeof(flash_dev),
				(uint8_t *)&flash_dev)) {
		LOG_ERR("Failed to get flash device element");
		return 0;
	}

	if (flash_dev.fw_count == 0) {
		LOG_ERR("Unknow firmware");
		return 0;
	}

	read_address += sizeof(flash_dev);

	// PFM Firmware Element Offset
	struct pfm_firmware_element fw_element;

	if (pfr_spi_read(spi_dev, read_address, sizeof(fw_element),
				(uint8_t *)&fw_element)) {
		LOG_ERR("Failed to get PFM firmware element");
		return 0;
	}

	// id length should be 4 byte aligned
	alignment = (fw_element.id_length % 4) ? (4 - (fw_element.id_length % 4)) : 0;
	id_length = fw_element.id_length + alignment;
	read_address += sizeof(fw_element) - sizeof(fw_element.id) + id_length;

	// PFM Firmware Version Element Offset
	struct pfm_firmware_version_element fw_ver_element;

	if (pfr_spi_read(spi_dev, read_address, sizeof(fw_ver_element),
				(uint8_t *)&fw_ver_element)) {
		LOG_ERR("Failed to get PFM firmware version element");
		return 0;
	}

	*region_cnt = fw_ver_element.rw_count;

	// version length should be 4 byte aligned
	alignment = (fw_ver_element.version_length % 4) ?
		(4 - (fw_ver_element.version_length % 4)) : 0;
	uint8_t ver_length = fw_ver_element.version_length + alignment;
	read_address += sizeof(fw_ver_element) - sizeof(fw_ver_element.version) + ver_length;

	return read_address;
}
#endif // CONFIG_CERBERUS_PFR
