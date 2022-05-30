/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <firmware/app_context.h>

struct Context_Manager {
	uint8_t status;
	uint16_t update_on_reset: 1;
	uint16_t cpld_update: 1;
	uint16_t pch_update: 1;
	uint16_t pch_update_active: 1;
	uint16_t pch_update_recovery: 1;
	uint16_t bmc_update: 1;
	uint16_t bmc_update_active: 1;
	uint16_t bmc_update_recovery: 1;
	uint16_t bmc_2_pch_update: 1;
	uint16_t bmc_2_pch_update_active: 1;
	uint16_t bmc_2_pch_update_recovery: 1;
	uint16_t platform_decommissionined: 1;
	uint16_t platform_provisioned: 1;
};

int app_context_init(struct app_context *context);
struct app_context *getappcontextInstance(void);
static int save_cpld_context(struct app_context *context);

