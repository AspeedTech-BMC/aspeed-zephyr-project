/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include "platform_monitor_ctrl.h"

LOG_MODULE_REGISTER(monitor_genoa, CONFIG_LOG_DEFAULT_LEVEL);

extern uint8_t gWdtBootStatus;

static struct gpio_callback rst_pltrst_cb_data;

/* Arm the ACM watchdog timer when ROT firmware detects a platform reset
 * through PLTRST# GPI signal.
 */
static void platform_genoa_reset_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);

	LOG_INF("[Platform->PFR] PLTRST[%s %d] = %d", dev->name, gpio_pin, ret);
}

/* Monitor Platform Reset Status */
static void platform_genoa_reset_monitor_init(void)
{
	int ret;
	struct gpio_dt_spec rst_pltrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_genoa), rst_pltrst_in_gpios, 0);

	ret = gpio_pin_configure_dt(&rst_pltrst, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", rst_pltrst.port->name, rst_pltrst.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&rst_pltrst, GPIO_INT_EDGE_RISING);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&rst_pltrst_cb_data, platform_genoa_reset_handler, BIT(rst_pltrst.pin));
	ret = gpio_add_callback(rst_pltrst.port, &rst_pltrst_cb_data);
	LOG_INF("Platform: gpio_add_callback = %d", ret);
}

static void platform_genoa_reset_monitor_remove(void)
{
	struct gpio_dt_spec rst_pltrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_genoa), rst_pltrst_in_gpios, 0);

	gpio_pin_interrupt_configure_dt(&rst_pltrst, GPIO_INT_DISABLE);
	gpio_remove_callback(rst_pltrst.port, &rst_pltrst_cb_data);
}

void platform_genoa_monitor_init(void)
{
	platform_genoa_reset_monitor_init();
}

void platform_genoa_monitor_remove(void)
{
	platform_genoa_reset_monitor_remove();
}

static const struct platform_monitor_ctrl_ops genoa_platform_monitor_ops = {
	.init = platform_genoa_monitor_init,
	.remove = platform_genoa_monitor_remove,
};

const struct platform_monitor_ctrl_ops *get_platform_monitor_ctrl_ops(void)
{
	return &genoa_platform_monitor_ops;
}
