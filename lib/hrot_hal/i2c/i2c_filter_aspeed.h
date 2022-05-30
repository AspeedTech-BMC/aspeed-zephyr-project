/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#define I2C_FILTER_MIDDLEWARE_PREFIX		"I2C_FILTER_"
#define I2C_FILTER_MIDDLEWARE_STRING_SIZE	sizeof("xxx")
#define I2C_FILTER_MIDDLEWARE_DEV_NAME_SIZE	(sizeof(I2C_FILTER_MIDDLEWARE_PREFIX) + I2C_FILTER_MIDDLEWARE_STRING_SIZE - 1)

int i2c_filter_middleware_set_whitelist(uint8_t filter_sel, uint8_t whitelist_tbl_idx, uint8_t slv_addr, void *whitelist_tbl);
int i2c_filter_middleware_en(uint8_t filter_sel, bool en);
int i2c_filter_middleware_init(uint8_t filter_sel);

