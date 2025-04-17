/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/drivers/spi_nor.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <zephyr/drivers/gpio.h>
#include "platform_gpio_ctrl.h"

#define LOG_MODULE_NAME gpio_egs

LOG_MODULE_REGISTER(LOG_MODULE_NAME);

static void pch_rst_enable_ctrl(bool enable)
{
	int ret;
	const struct gpio_dt_spec rst_gpio =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common),
						pch_rst_ctrl_out_gpios, 0);

	if (enable) {
		gpio_pin_set(rst_gpio.port, rst_gpio.pin, 0);
	} else {
		gpio_pin_set(rst_gpio.port, rst_gpio.pin, 1);
	}

	ret = gpio_pin_configure_dt(&rst_gpio, GPIO_OUTPUT);
	if (ret)
		return;

	k_busy_wait(10000); /* 10ms */
}

static void EgsPchHold(void)
{
	pch_rst_enable_ctrl(true);
}

static void EgsPchRelease(void)
{
	pch_rst_enable_ctrl(false);
}

static const struct platform_gpio_ctrl_ops egs_gpio_ops = {
	.pch_hold = EgsPchHold,
	.pch_release = EgsPchRelease,
};

const struct platform_gpio_ctrl_ops *get_platform_gpio_ctrl_ops(void)
{
	return &egs_gpio_ops;
}
