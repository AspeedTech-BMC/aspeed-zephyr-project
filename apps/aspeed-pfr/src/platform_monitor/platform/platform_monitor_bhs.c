/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include "gpio/gpio_aspeed.h"
#include "platform_monitor_ctrl.h"

LOG_MODULE_REGISTER(monitor_bhs, CONFIG_LOG_DEFAULT_LEVEL);

extern struct k_sem pltrst_sem;

static struct gpio_callback rst_pltrst_cb_data;
extern bool i3c_hub_configured;

/**
 * Arm the ACM watchdog timer when ROT firmware detects a platform reset
 * through PLTRST# GPI signal.
 */
static void platform_bhs_reset_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);
	LOG_INF("[CPU->PFR] PLTRST_SYNC[%s %d] = %d", dev->name, gpio_pin, ret);

	if (ret == 0) {
		RSTPlatformReset(true);
	} else {
		RSTPlatformReset(false);
		extern bool pltrst_sync;
		pltrst_sync = true;
#if defined(CONFIG_PFR_MCTP_I3C)
		k_sem_give(&pltrst_sem);
#endif
	}
}

/* Monitor Platform Reset Status */
static void platform_bhs_reset_monitor_init(void)
{
	int ret;
	struct gpio_dt_spec rst_pltrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), rst_pltrst_in_gpios, 0);

	ret = gpio_pin_configure_dt(&rst_pltrst, GPIO_INPUT);
	LOG_INF("Platform: gpio_pin_configure_dt[%s %d] = %d", rst_pltrst.port->name, rst_pltrst.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&rst_pltrst, GPIO_INT_EDGE_BOTH);
	LOG_INF("Platform: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&rst_pltrst_cb_data, platform_bhs_reset_handler, BIT(rst_pltrst.pin));
	ret = gpio_add_callback(rst_pltrst.port, &rst_pltrst_cb_data);
	LOG_INF("Platform: gpio_add_callback = %d", ret);
}

static void platform_bhs_reset_monitor_remove(void)
{
	struct gpio_dt_spec rst_pltrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), rst_pltrst_in_gpios, 0);

	gpio_pin_interrupt_configure_dt(&rst_pltrst, GPIO_INT_DISABLE);
	gpio_remove_callback(rst_pltrst.port, &rst_pltrst_cb_data);
}

void platform_bhs_monitor_init(void)
{
	platform_bhs_reset_monitor_init();
}

void platform_bhs_monitor_remove(void)
{
	platform_bhs_reset_monitor_remove();
}

struct k_work pwr_btn_work;
static struct gpio_callback fp_pwr_btn_cb_data;

static void power_btn_passthrough_update()
{
	struct gpio_dt_spec power_btn_in =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), fp_pwr_btn_in_gpios, 0);
	struct gpio_dt_spec power_btn_out =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), bmc_pwr_btn_out_gpios, 0);
	int ret = gpio_pin_get(power_btn_in.port, power_btn_in.pin);

	LOG_INF("[FP->PFR] PWR_BTN[%s %d] = %d", power_btn_in.port->name, power_btn_in.pin, ret);
	gpio_pin_set(power_btn_out.port, power_btn_out.pin, ret);
	gpio_pin_configure_dt(&power_btn_out, GPIO_OUTPUT);
	LOG_INF("[PFR->BMC] PWR_BTN[%s %d] = %d", power_btn_out.port->name, power_btn_out.pin, ret);
}

static void power_btn_work_handler(struct k_work *item)
{
	power_btn_passthrough_update();
}

void power_btn_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	LOG_INF("[FP->PFR] PWN_BTN Interrupt");
	k_work_submit(&pwr_btn_work);
}

void bhs_power_btn(bool enable)
{
	static bool init_done = false;
	struct gpio_dt_spec power_btn_in =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), fp_pwr_btn_in_gpios, 0);
	struct gpio_dt_spec power_btn_out =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), bmc_pwr_btn_out_gpios, 0);

	if (!init_done) {
		k_work_init(&pwr_btn_work, power_btn_work_handler);
		gpio_init_callback(&fp_pwr_btn_cb_data, power_btn_handler, BIT(power_btn_in.pin));
		init_done = true;
	}

	LOG_INF("[FP->PFR] Monitor PWN_BTN[%s %d] %s",
			power_btn_in.port->name, power_btn_in.pin, enable ? "registered" : "removed");
	if (enable) {
		/* Register input */
		gpio_pin_configure_dt(&power_btn_in, GPIO_INPUT);
		gpio_add_callback(power_btn_in.port, &fp_pwr_btn_cb_data);
		gpio_pin_interrupt_configure_dt(&power_btn_in, GPIO_INT_EDGE_BOTH);

		/* Update PIN state at T0 */
		power_btn_passthrough_update();
	} else {
		/* Remove the callback */
		gpio_pin_interrupt_configure_dt(&power_btn_in, GPIO_INT_DISABLE);
		gpio_remove_callback(power_btn_in.port, &fp_pwr_btn_cb_data);

		/* Force to high at T-1 */
		LOG_INF("[PFR->BMC] T-1 PWR_BTN[%s %d] force to 1",
	  		power_btn_out.port->name, power_btn_out.pin);
		gpio_pin_set(power_btn_out.port, power_btn_out.pin, 1);
	}
}

static const struct platform_monitor_ctrl_ops bhs_platform_monitor_ops = {
	.init = platform_bhs_monitor_init,
	.remove = platform_bhs_monitor_remove,
	.power_btn = bhs_power_btn,
};

const struct platform_monitor_ctrl_ops *get_platform_monitor_ctrl_ops(void)
{
	return &bhs_platform_monitor_ops;
}
