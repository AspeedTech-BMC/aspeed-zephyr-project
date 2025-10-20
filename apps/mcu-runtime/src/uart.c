/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <ast_loader.h>
#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yModem.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(ast_uart, CONFIG_SOC_FMC_LOG_LEVEL);

struct ymodem_port uport = {
	.write = writec,
	.read = readc,
	.rx_timeout_ms = 3000,
	.max_retries = 20,
};

static int uart_init(struct device *dev)
{
	return 0;
}

static int uart_load(struct device *dev, uint32_t *dst, uint32_t *len)
{
	uint32_t out_sz = 0;
	enum ymodem_status sts = YMODEM_OK;

	if (!dev)
		return -1;

	ymodem_open(dev);

	sts = ymodem_receive_into(&uport, (uint8_t *)dst, &out_sz, NULL, 0);
	if (sts == YMODEM_OK)
		*len = out_sz;
	else
		*len = 0;

	ymodem_close();

	return (int)sts;
}

static struct ast_loader_ops bootuart_ops = {
	.init = uart_init,
	.load = uart_load,
};

int uart_register(struct ast_loader *loader)
{
	struct device *dev;

	dev = (struct device *)device_get_binding("serial@14c33b00");
	if (!dev) {
		LOG_ERR("Cannot bind uart device correctly");
		return -1;
	}

	loader->ops = &bootuart_ops;
	loader->dev = dev;

	LOG_DBG("UART loader registered");

	return 0;
}
