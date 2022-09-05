/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>

uint32_t cerberus_get_rw_region_addr(int spi_dev, uint32_t pfm_addr, uint16_t *region_cnt);
