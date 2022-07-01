/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_SPI_MUX_INVERSE)
#define SPIM_EXT_MUX_BMC_PCH        SPIM_EXT_MUX_SEL_1
#define SPIM_EXT_MUX_ROT            SPIM_EXT_MUX_SEL_0
#else
#define SPIM_EXT_MUX_BMC_PCH        SPIM_EXT_MUX_SEL_0
#define SPIM_EXT_MUX_ROT            SPIM_EXT_MUX_SEL_1
#endif


#define BMC_SPI_MONITOR "spi_m1"
#define PCH_SPI_MONITOR "spi_m3"
#define CPU0_RST 1  //refer to ASPEED Datasheet V0.8 p.41
#define BMC_SRST 5

#include <zephyr/types.h>
#include <stddef.h>
#include <device.h>

enum {
	GPIO_APP_CMD_NOOP  = 0x00,				/**< No-op */
};

int BMCBootHold(void);
int PCHBootHold(void);
int BMCBootRelease(void);
int PCHBootRelease(void);
