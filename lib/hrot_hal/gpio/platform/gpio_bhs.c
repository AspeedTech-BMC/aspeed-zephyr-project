/*
 * Copyright (c) 2025 ASPEED Technology Inc.
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
#include "../gpio_aspeed.h"

#define LOG_MODULE_NAME gpio_bhs

LOG_MODULE_REGISTER(LOG_MODULE_NAME);

void AUXPowerGoodControl(bool assert)
{
	const struct gpio_dt_spec aux_pwrgd_cpu0 =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), pwrgd_cpu0_out_gpios, 0);
	const struct gpio_dt_spec aux_pwrgd_cpu1 =
		GPIO_DT_SPEC_GET_OR(DT_INST(0, aspeed_pfr_gpio_bhs), pwrgd_cpu1_out_gpios, {0});

	if (assert) {
		LOG_INF("[PFR->CPLD] AUX_PWRGD_CPU0 Assert[%s %d]", aux_pwrgd_cpu0.port->name, aux_pwrgd_cpu0.pin);
		gpio_pin_set(aux_pwrgd_cpu0.port, aux_pwrgd_cpu0.pin, 1);
		if (aux_pwrgd_cpu1.port) {
			LOG_INF("[PFR->CPLD] AUX_PWRGD_CPU1 Assert[%s %d]", aux_pwrgd_cpu1.port->name, aux_pwrgd_cpu1.pin);
			gpio_pin_set(aux_pwrgd_cpu1.port, aux_pwrgd_cpu1.pin, 1);
		}
	} else {
		LOG_INF("[PFR->CPLD] AUX_PWRGD_CPU0 De-assert[%s %d]", aux_pwrgd_cpu0.port->name, aux_pwrgd_cpu0.pin);
		gpio_pin_set(aux_pwrgd_cpu0.port, aux_pwrgd_cpu0.pin, 0);
		if (aux_pwrgd_cpu1.port) {
			LOG_INF("[PFR->CPLD] AUX_PWRGD_CPU1 De-assert[%s %d]", aux_pwrgd_cpu1.port->name, aux_pwrgd_cpu1.pin);
			gpio_pin_set(aux_pwrgd_cpu1.port, aux_pwrgd_cpu1.pin, 0);
		}
	}

	gpio_pin_configure_dt(&aux_pwrgd_cpu0, GPIO_OUTPUT);
	if (aux_pwrgd_cpu1.port)
		gpio_pin_configure_dt(&aux_pwrgd_cpu1, GPIO_OUTPUT);
}

void BhsRSTPlatformReset(bool assert)
{
	const struct gpio_dt_spec rst_pltrst_cpu0 =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), rst_pltrst_cpu0_out_gpios, 0);
	const struct gpio_dt_spec rst_pltrst_cpu1 =
		GPIO_DT_SPEC_GET_OR(DT_INST(0, aspeed_pfr_gpio_bhs), rst_pltrst_cpu1_out_gpios, {0});

	if (assert) {
		LOG_INF("[PFR->CPLD] PLTRSTN_CPU0 Assert[%s %d]", rst_pltrst_cpu0.port->name, rst_pltrst_cpu0.pin);
		gpio_pin_set(rst_pltrst_cpu0.port, rst_pltrst_cpu0.pin, 0);
		if (rst_pltrst_cpu1.port) {
			LOG_INF("[PFR->CPLD] PLTRSTN_CPU1 Assert[%s %d]", rst_pltrst_cpu1.port->name, rst_pltrst_cpu1.pin);
			gpio_pin_set(rst_pltrst_cpu1.port, rst_pltrst_cpu1.pin, 0);
		}
	} else {
		LOG_INF("[PFR->CPLD] PLTRSTN_CPU0 De-assert[%s %d]", rst_pltrst_cpu0.port->name, rst_pltrst_cpu0.pin);
		gpio_pin_set(rst_pltrst_cpu0.port, rst_pltrst_cpu0.pin, 1);
		if (rst_pltrst_cpu1.port) {
			LOG_INF("[PFR->CPLD] PLTRSTN_CPU1 De-assert[%s %d]", rst_pltrst_cpu1.port->name, rst_pltrst_cpu1.pin);
			gpio_pin_set(rst_pltrst_cpu1.port, rst_pltrst_cpu1.pin, 1);
		}
	}

	gpio_pin_configure_dt(&rst_pltrst_cpu0, GPIO_OUTPUT);
	if (rst_pltrst_cpu1.port)
		gpio_pin_configure_dt(&rst_pltrst_cpu1, GPIO_OUTPUT);
}

void BhsRTCRSTControl(bool assert)
{
	const struct gpio_dt_spec rtc_rst_cpu0 =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_bhs), rst_rtcrst_cpu0_out_gpios, 0);
	const struct gpio_dt_spec rtc_rst_cpu1 =
		GPIO_DT_SPEC_GET_OR(DT_INST(0, aspeed_pfr_gpio_bhs), rst_rtcrst_cpu1_out_gpios, {0});

	if (assert) {
		LOG_INF("[PFR->CPLD] RTC_RST_CPU0 Assert[%s %d]", rtc_rst_cpu0.port->name, rtc_rst_cpu0.pin);
		gpio_pin_set(rtc_rst_cpu0.port, rtc_rst_cpu0.pin, 0);
		if (rtc_rst_cpu1.port) {
			LOG_INF("[PFR->CPLD] RTC_RST_CPU1 Assert[%s %d]", rtc_rst_cpu1.port->name, rtc_rst_cpu1.pin);
			gpio_pin_set(rtc_rst_cpu1.port, rtc_rst_cpu1.pin, 0);
		}
	} else {
		LOG_INF("[PFR->CPLD] RTC_RST_CPU0 De-assert[%s %d]", rtc_rst_cpu0.port->name, rtc_rst_cpu0.pin);
		gpio_pin_set(rtc_rst_cpu0.port, rtc_rst_cpu0.pin, 1);
		if (rtc_rst_cpu1.port) {
			LOG_INF("[PFR->CPLD] RTC_RST_CPU1 De-assert[%s %d]", rtc_rst_cpu1.port->name, rtc_rst_cpu1.pin);
			gpio_pin_set(rtc_rst_cpu1.port, rtc_rst_cpu1.pin, 1);
		}
	}

	gpio_pin_configure_dt(&rtc_rst_cpu0, GPIO_OUTPUT);
	if (rtc_rst_cpu1.port)
		gpio_pin_configure_dt(&rtc_rst_cpu1, GPIO_OUTPUT);
}

#if defined(CONFIG_PFR_MCTP_I3C)
extern int i3c_mng_mux_owner;
void BhsSwitchI3cMng(int owner)
{
	const struct gpio_dt_spec i3c_mng_owner =
		GPIO_DT_SPEC_GET_OR(DT_INST(0, aspeed_pfr_gpio_bhs),
						i3c_mng_mux_sel_out_gpios,
						{0});

	if (gpio_is_ready_dt(&i3c_mng_owner) == false) {
		LOG_ERR("I3C MNG Owner GPIO is not ready");
		return;
	}

	gpio_pin_configure_dt(&i3c_mng_owner, GPIO_OUTPUT);
	LOG_INF("Switch I3C MNG Owner to %s", owner == I3C_MNG_OWNER_BMC ? "BMC" : "ROT");
	gpio_pin_set(i3c_mng_owner.port, i3c_mng_owner.pin, owner);
	i3c_mng_mux_owner = owner;
}
#endif

static void BhsPchHold(void)
{
	BhsRSTPlatformReset(true);
	AUXPowerGoodControl(false);
}

static void BhsPchRelease(void)
{
	AUXPowerGoodControl(true);
}

static const struct platform_gpio_ctrl_ops bhs_gpio_ops = {
	.pch_hold = BhsPchHold,
	.pch_release = BhsPchRelease,
	.rst_pltrst = BhsRSTPlatformReset,
	.rst_rtcrst = BhsRTCRSTControl,
#if defined(CONFIG_PFR_MCTP_I3C)
	.i3c_mng_switch = BhsSwitchI3cMng,
#endif
};

const struct platform_gpio_ctrl_ops *get_platform_gpio_ctrl_ops(void)
{
	return &bhs_gpio_ops;
}
