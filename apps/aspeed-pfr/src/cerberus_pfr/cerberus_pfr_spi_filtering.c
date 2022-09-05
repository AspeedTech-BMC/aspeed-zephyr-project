/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_CERBERUS_PFR)

#include <stdint.h>
#include <logging/log.h>
#include "common/common.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_common.h"
#include "flash/flash_aspeed.h"
#include "pfr/pfr_util.h"
#include "Smbus_mailbox/Smbus_mailbox.h"

#define SPIM_NUM  4

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

void apply_pfm_protection(int spi_dev)
{
	char *spim_devs[SPIM_NUM] = {
		"spi_m1",
		"spi_m2",
		"spi_m3",
		"spi_m4"
	};

	uint32_t region_start_address;
	uint32_t region_end_address;
	uint32_t pfm_addr;
	uint32_t rw_region_addr;
	uint16_t region_cnt;
	int region_length;

#if defined(CONFIG_BMC_DUAL_FLASH)
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();
	int flash_size;
#endif

	if (spi_dev == BMC_SPI)
		get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, (uint8_t *)&pfm_addr,
				sizeof(pfm_addr));
	else if (spi_dev == PCH_SPI)
		get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)&pfm_addr,
				sizeof(pfm_addr));

	rw_region_addr = cerberus_get_rw_region_addr(spi_dev, pfm_addr, &region_cnt);
	if (rw_region_addr == 0) {
		LOG_ERR("Failed to get read write regions");
		return;
	}

	struct pfm_fw_version_element_rw_region rw_region;
	for (int i = 0; i < region_cnt; i++) {
		if (pfr_spi_read(spi_dev, rw_region_addr, sizeof(rw_region), (uint8_t *)&rw_region)) {
			LOG_ERR("Failed to get read/write regions");
			return;
		}

		region_start_address = rw_region.region.start_addr;
		region_end_address = rw_region.region.end_addr;
		region_length = region_end_address - region_start_address + 1;

#if defined(CONFIG_BMC_DUAL_FLASH)
		spi_flash->spi.base.get_device_size((struct flash *)&spi_flash->spi, &flash_size);
		if (region_start_address >= flash_size && region_end_address >= flash_size) {
			region_start_address -= flash_size;
			region_end_address -= flash_size;
			spi_dev = BMC_SPI_2;
		}
#endif
		Set_SPI_Filter_RW_Region(spim_devs[spi_dev],
				SPI_FILTER_WRITE_PRIV, SPI_FILTER_PRIV_ENABLE,
				region_start_address, region_length);
		LOG_INF("SPI_ID[%d] write enable 0x%08x to 0x%08x",
				spi_dev, region_start_address, region_end_address);
		rw_region_addr += sizeof(rw_region);
	}

	SPI_Monitor_Enable(spim_devs[spi_dev], true);
}

#endif // CONFIG_CERBERUS_PFR
