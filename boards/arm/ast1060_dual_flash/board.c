/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <init.h>
#include <zephyr.h>
#include <drivers/gpio.h>

static int ast1060_dcscm_post_init(const struct device *arg)
{
	// Enable flash power by GPIOL2 and GPIOL3
	const struct device *dev;
	dev = device_get_binding("GPIO0_I_L");
	gpio_pin_configure(dev, 26, GPIO_OUTPUT_ACTIVE);
	gpio_pin_configure(dev, 27, GPIO_OUTPUT_ACTIVE);
	return 0;
}

static int ast1060_dcscm_init(const struct device *arg)
{
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	const struct device *dev;
	dev = device_get_binding("GPIO0_E_H");
	gpio_pin_configure(dev, 27, GPIO_OUTPUT_ACTIVE);
#endif

	return 0;
}

SYS_INIT(ast1060_dcscm_post_init, POST_KERNEL, 60);
SYS_INIT(ast1060_dcscm_init, APPLICATION, 0);
