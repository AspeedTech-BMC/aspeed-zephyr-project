/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <kernel.h>
#include <sys/util.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr.h>
#include <device.h>

#include "I2C_wrapper.h"
#include <i2c/I2C_Slave_aspeed.h>

/* I2CSlave_wrapper_InitSlaveDev
 * I2c salve initial wrapper to asp1060 api.
 *
 * @param i2c                   structure i2c_slave_interface
 * @param DevName               I2C device name, support I2C_0 and I2C_1
 * @param slave_addr	I2c slave device slave address
 *
 * @return 0 if the I2C slave was successfully initialize or an error code.
 */
int I2CSlave_wrapper_InitSlaveDev(struct i2c_slave_interface *i2c, char *DevName, uint8_t slave_addr)
{
	const struct device *dev;

	dev = device_get_binding(DevName);

	if (!dev) {
		return I2C_SLAVE_NO_DEVICE;
	}
	printk("\r\n I2CSlave_wrapper_InitSlaveDev get device\r\n");
	return ast_i2c_slave_dev_init(dev, slave_addr);;
}

/**
 * Initialize an aspeed I2C slave engine.
 *
 * @param engine The I2C slave to initialize.
 *
 * @return 0 if the I2C slave was successfully initialize or an error code.
 */
int I2C_Slave_wrapper_init(struct I2CSlave_engine_wrapper *I2CSlaveEngine)
{
	int status;

	if (I2CSlaveEngine == NULL) {
		return I2C_SLAVE_INVALID_ARGUMENT;
	}

	memset(I2CSlaveEngine, 0, sizeof(struct I2CSlave_engine_wrapper));

	I2CSlaveEngine->base.InitSlaveDev = I2CSlave_wrapper_InitSlaveDev;

	return 0;
}
