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
#include <xyzModem.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(ast_uart, CONFIG_SOC_FMC_LOG_LEVEL);

static int uart_init(struct device *dev)
{
	return 0;
}

static int uart_load(struct device *dev, uint32_t *dst, uint32_t *len)
{
	int err;
	char *buf = (char *)dst;
	connection_info_t info;
	int total = 0;
	int ret;

	info.mode = xyzModem_ymodem;

	ret = xyzModem_stream_open(dev, &info, &err);
	if (ret < 0)
		return ret;

	while ((ret = xyzModem_stream_read(buf, 1024, &err)) > 0) {
		buf += ret;
		total += ret;
	}

	xyzModem_stream_close(&err);
	xyzModem_stream_terminate(false, &getcymodem);

	*len = total;

	if (total == 0)
		return -1;

	return 0;
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
