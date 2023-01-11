/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <stdint.h>

/* TODO: Loading these setting from PFM */
struct SMBUS_FILTER_DEVICE {

	uint8_t enable;
	uint8_t slave_addr; /* 8 Bit Address */
	uint8_t whitelist_cmd[32];
};

/* Each instance represent for a bus */
struct SMBUS_FILTER_MANIFEST {
	struct SMBUS_FILTER_DEVICE device[16];
};

void apply_pfm_smbus_protection(uint8_t smbus_filter);
