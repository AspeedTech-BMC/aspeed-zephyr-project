/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ZEPHYR_INCLUDE_GPIO_API_MIDLEYER_H_
#define ZEPHYR_INCLUDE_GPIO_API_MIDLEYER_H_

#define BMC_SPI_MONITOR "spi_m1"
#if !defined(CONFIG_ASPEED_DC_SCM)
#define PCH_SPI_MONITOR "spi_m2"
#else
#define PCH_SPI_MONITOR "spi_m3"
#endif
#define CPU0_RST 1  //refer to ASPEED Datasheet V0.8 p.41
#define BMC_SRST 5

#include <zephyr/types.h>
#include <stddef.h>
#include <device.h>

enum {
	GPIO_APP_CMD_NOOP  = 0x00,				/**< No-op */
};

#endif
