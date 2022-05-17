/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ZEPHYR_INCLUDE_SPI_FILTER_API_MIDLEYER_H_
#define ZEPHYR_INCLUDE_SPI_FILTER_API_MIDLEYER_H_

#include <zephyr/types.h>
#include <stddef.h>
#include <device.h>
#include <drivers/misc/aspeed/pfr_aspeed.h>

void SPI_Monitor_Enable(char *dev_name, bool enabled);
int Set_SPI_Filter_RW_Region(char *dev_name, enum addr_priv_rw_select rw_select, enum addr_priv_op op, mm_reg_t addr, uint32_t len);

#endif
