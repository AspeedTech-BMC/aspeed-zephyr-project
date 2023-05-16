/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include "pfr/pfr_common.h"

#pragma pack(1)
struct PFR_PFM_VERSION {
	uint8_t svn;
	uint8_t reserved1;
	uint8_t major;
	uint8_t reserved2;
	uint8_t minor;
	uint8_t reserved3;
};
#pragma pack()

int set_ufm_svn(uint32_t offset, uint8_t svn);
uint8_t get_ufm_svn(uint32_t offset);
int svn_policy_verify(uint32_t offset, uint32_t svn);
int does_staged_fw_image_match_active_fw_image(struct pfr_manifest *manifest);
int get_active_pfm_version_details(struct pfr_manifest *pfr_manifest);
int get_recover_pfm_version_details(struct pfr_manifest *pfr_manifest);

