/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <i2c/i2c_slave_common.h>

struct I2CSlave_engine_wrapper {
	struct i2c_slave_interface base;
};

int I2C_Slave_wrapper_init(struct I2CSlave_engine_wrapper *I2CSlaveEngine);
