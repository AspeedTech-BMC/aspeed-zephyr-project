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

#define LOG_MODULE_NAME gpio_bhs_prot

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

void ProtRSTPlatformReset(bool assert)
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

void ProtRTCRSTControl(bool assert)
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


static void ProtPchHold(void)
{
	ProtRSTPlatformReset(true);
	AUXPowerGoodControl(false);
	pch_rst_enable_ctrl(true);
}

static void ProtPchRelease(void)
{
	/* De-assert AUX_PWRGD_CPU0 and AUX_PWRGD_CPU1 */
	AUXPowerGoodControl(true);
	pch_rst_enable_ctrl(false);
}

static const struct platform_gpio_ctrl_ops bhs_prot_gpio_ops = {
	.pch_hold = ProtPchHold,
	.pch_release = ProtPchRelease,
	.rst_rtcrst = ProtRTCRSTControl,
	.rst_pltrst = ProtRSTPlatformReset,
};

const struct platform_gpio_ctrl_ops *get_platform_gpio_ctrl_ops(void)
{
	return &bhs_prot_gpio_ops;
}
