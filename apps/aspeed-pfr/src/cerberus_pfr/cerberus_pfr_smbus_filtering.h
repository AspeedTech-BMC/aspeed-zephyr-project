/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <stdint.h>


#pragma pack(1)
/* TODO: Loading these setting from PFM */
struct SMBUS_FILTER_DEVICE {

	uint8_t enable;
	uint8_t slave_addr; /* 8 Bit Address */
	uint8_t whitelist_cmd[32];
};

/* Each instance represent for a bus */
struct SMBUS_FILTER_MANIFEST {
	uint8_t filter_id;
	uint8_t device_count;
};

struct SMBUS_FILTER_RULE {
	uint32_t magic_number;
	uint8_t filter_count;
};
#pragma pack()

void apply_pfm_smbus_protection(uint8_t spi_dev);
