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

LOG_MODULE_REGISTER(ast_usb, CONFIG_SOC_FMC_LOG_LEVEL);

static int usb_init(struct device *dev)
{
	return 0;
}

static int usb_load(struct device *dev, uint32_t *dst, uint32_t *len)
{

	return 0;
}

static struct ast_loader_ops bootusb_ops = {
	.init = usb_init,
	.load = usb_load,
};

int usb_register(struct ast_loader *loader)
{
	struct device *dev;

	dev = (struct device *)device_get_binding("usb@xxxxxxxx");
	if (!dev) {
		LOG_ERR("No device named usb");
		return -1;
	}

	loader->ops = &bootusb_ops;
	loader->dev = dev;

	LOG_DBG("USB loader registered");

	return 0;
}
