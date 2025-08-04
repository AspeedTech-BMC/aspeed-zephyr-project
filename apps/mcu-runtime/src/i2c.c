// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
 */

#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/logging/log.h>
#include <scu_ast2700.h>
#include <ast_loader.h>

LOG_MODULE_REGISTER(ast_i2c, CONFIG_SOC_FMC_LOG_LEVEL);

static int i2c_init(struct device *dev)
{
	return 0;
}

static int i2c_load(struct device *dev, uint32_t *dst, uint32_t *len)
{

	return 0;
}

static struct ast_loader_ops booti2c_ops = {
	.init = i2c_init,
	.load = i2c_load,
};

int i2c_register(struct ast_loader *loader)
{
	struct device *dev;

	dev = (struct device *)device_get_binding("i2c@xxxxxxxx");
	if (!dev) {
		LOG_ERR("No device named i2c");
		return -1;
	}

	loader->ops = &booti2c_ops;
	loader->dev = dev;

	LOG_DBG("I2C loader registered");

	return 0;
}
