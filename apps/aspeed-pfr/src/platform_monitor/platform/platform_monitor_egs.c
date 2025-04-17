/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include "include/SmbusMailBoxCom.h"
#include "watchdog_timer/wdt_utils.h"
#include "watchdog_timer/wdt_handler.h"
#include "gpio/gpio_aspeed.h"
#include "platform_monitor_ctrl.h"

LOG_MODULE_REGISTER(monitor_egs, CONFIG_LOG_DEFAULT_LEVEL);

extern uint8_t gWdtBootStatus;

static struct gpio_callback rst_pltrst_cb_data;

/**
 * Arm the ACM watchdog timer when ROT firmware detects a platform reset
 * through PLTRST# GPI signal.
 */
static void platform_egs_reset_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);
	uint32_t ms_timeout = WDT_ACM_TIMER_MAXTIMEOUT;
	int type = ACM_TIMER;

	LOG_INF("[Platform->PFR] PLTRST[%s %d] = %d", dev->name, gpio_pin, ret);

	// Clear previous boot done status
	gWdtBootStatus &= ~WDT_ACM_BIOS_BOOT_DONE_MASK;
	// Start ACM watchdog timer
	pfr_start_timer(type, ms_timeout);
}

/* Monitor Platform Reset Status */
static void platform_egs_reset_monitor_init(void)
{
	int ret;
	struct gpio_dt_spec rst_pltrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_egs), rst_pltrst_in_gpios, 0);

	ret = gpio_pin_configure_dt(&rst_pltrst, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", rst_pltrst.port->name, rst_pltrst.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&rst_pltrst, GPIO_INT_EDGE_RISING);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&rst_pltrst_cb_data, platform_egs_reset_handler, BIT(rst_pltrst.pin));
	ret = gpio_add_callback(rst_pltrst.port, &rst_pltrst_cb_data);
	LOG_INF("Platform: gpio_add_callback = %d", ret);
}

static void platform_egs_reset_monitor_remove(void)
{
	struct gpio_dt_spec rst_pltrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_egs), rst_pltrst_in_gpios, 0);

	gpio_pin_interrupt_configure_dt(&rst_pltrst, GPIO_INT_DISABLE);
	gpio_remove_callback(rst_pltrst.port, &rst_pltrst_cb_data);
}

static struct gpio_callback me_authn_fail_cb_data;
static struct gpio_callback me_bt_done_cb_data;

/**
 * ME_AUTHN_FAIL: 1 means ME Authentication Failed
 */
static void me_auth_fail_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);

	LOG_INF("[ME->PFR] ME_AUTHN_FAIL[%s %d] = %d", dev->name, gpio_pin, ret);
	me_wdt_timer_handler(AUTHENTICATION_FAILED);
}

/**
 * ME_BT_DONE: 1 means ME Boot Done
 */
static void me_boot_done_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);

	LOG_INF("[ME->PFR] ME_BT_DONE[%s %d] = %d", dev->name, gpio_pin, ret);
	me_wdt_timer_handler(EXECUTION_BLOCK_COMPLETED);
}

/* Monitor ME boot Status */
static void me_boot_monitor_init(void)
{
	int ret;
	struct gpio_dt_spec me_bt_done =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_egs), me_bt_done_in_gpios, 0);
	struct gpio_dt_spec me_authn_fail =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_egs), me_authn_fail_in_gpios, 0);

	ret = gpio_pin_configure_dt(&me_bt_done, GPIO_INPUT);
	LOG_INF("ME: gpio_pin_configure_dt[%s %d] = %d", me_bt_done.port->name, me_bt_done.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&me_bt_done, GPIO_INT_EDGE_RISING);
	LOG_INF("ME: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&me_bt_done_cb_data, me_boot_done_handler, BIT(me_bt_done.pin));
	ret = gpio_add_callback(me_bt_done.port, &me_bt_done_cb_data);
	LOG_INF("ME: gpio_add_callback = %d", ret);

	ret = gpio_pin_configure_dt(&me_authn_fail, GPIO_INPUT);
	LOG_INF("ME: gpio_pin_configure_dt[%s %d] = %d", me_authn_fail.port->name, me_authn_fail.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&me_authn_fail, GPIO_INT_EDGE_RISING);
	LOG_INF("ME: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&me_authn_fail_cb_data, me_auth_fail_handler, BIT(me_authn_fail.pin));
	ret = gpio_add_callback(me_authn_fail.port, &me_authn_fail_cb_data);
	LOG_INF("ME: gpio_add_callback = %d", ret);
}

static void me_boot_monitor_remove(void)
{
	struct gpio_dt_spec me_bt_done =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_egs), me_bt_done_in_gpios, 0);
	struct gpio_dt_spec me_authn_fail =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_egs), me_authn_fail_in_gpios, 0);

	gpio_pin_interrupt_configure_dt(&me_bt_done, GPIO_INT_DISABLE);
	gpio_remove_callback(me_bt_done.port, &me_bt_done_cb_data);
	gpio_pin_interrupt_configure_dt(&me_authn_fail, GPIO_INT_DISABLE);
	gpio_remove_callback(me_authn_fail.port, &me_authn_fail_cb_data);
}


void platform_egs_monitor_init(void)
{
	platform_egs_reset_monitor_init();
	me_boot_monitor_init();
}

void platform_egs_monitor_remove(void)
{
	platform_egs_reset_monitor_remove();
	me_boot_monitor_remove();
}

static const struct platform_monitor_ctrl_ops egs_platform_monitor_ops = {
	.init = platform_egs_monitor_init,
	.remove = platform_egs_monitor_remove,
};

const struct platform_monitor_ctrl_ops *get_platform_monitor_ctrl_ops(void)
{
	return &egs_platform_monitor_ops;
}
