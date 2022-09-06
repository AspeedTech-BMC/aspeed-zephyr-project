/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_CERBERUS_PFR)
#include <stdint.h>
#include "cerberus_pfr_recovery.h"
#include "pfr/pfr_common.h"
#include "manifest/pfm/pfm_format.h"

int cerberus_get_rw_region_info(int spi_dev, uint32_t pfm_addr, uint32_t *rw_region_addr,
		struct pfm_firmware_version_element *fw_ver_element);
int cerberus_get_image_pfm_addr(struct pfr_manifest *manifest,
		struct recovery_header *image_header, uint32_t *src_pfm_addr,
		uint32_t *dest_pfm_addr);
uint32_t *cerberus_get_update_regions(struct pfr_manifest *manifest,
		struct recovery_header *image_header, uint32_t *region_cnt);

#endif // CONFIG_CERBERUS_PFR
