/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <abr.h>

#define WDT_ABR_CTRL            0x4c
#define WDT_ABR_INDICATOR       BIT(1)

bool abr_enabled(void)
{
	return (sys_read32(ABR_REG) & ABR_EN);
}

uint32_t abr_get_id(void)
{
	uint32_t val;

	val = !!(sys_read32(WDTA_REG + WDT_ABR_CTRL) & WDT_ABR_INDICATOR);

	return val;
}
