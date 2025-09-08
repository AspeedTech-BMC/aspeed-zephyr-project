/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/logging/log.h>
#include <scu_ast2700.h>
#include <ast_loader.h>

LOG_MODULE_REGISTER(ast_uart, CONFIG_SOC_FMC_LOG_LEVEL);

static int uart_init(struct device *dev)
{
	return 0;
}

static int uart_load(struct device *dev, uint32_t *dst, uint32_t *len)
{

	return 0;
}

static struct ast_loader_ops bootuart_ops = {
	.init = uart_init,
	.load = uart_load,
};

int uart_register(struct ast_loader *loader)
{
	struct device *dev;

	dev = (struct device *)device_get_binding("uart@xxxxxxxx");
	if (!dev) {
		LOG_ERR("No device named uart");
		return -1;
	}

	loader->ops = &bootuart_ops;
	loader->dev = dev;

	LOG_DBG("UART loader registered");

	return 0;
}
