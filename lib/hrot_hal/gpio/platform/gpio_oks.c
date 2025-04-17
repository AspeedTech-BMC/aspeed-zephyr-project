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

#define LOG_MODULE_NAME gpio_oks

LOG_MODULE_REGISTER(LOG_MODULE_NAME);

void AUXPowerGoodControl(bool assert)
{
	const struct gpio_dt_spec aux_pwrgd_cpu0 =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pwrgd_cpu0_out_gpios, 0);
	const struct gpio_dt_spec aux_pwrgd_cpu1 =
		GPIO_DT_SPEC_GET_OR(DT_INST(0, aspeed_pfr_gpio_oks), pwrgd_cpu1_out_gpios, {0});

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

void ClearS0Attestation(void)
{
	const struct gpio_dt_spec pfr_s0_att_done =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pfr_s0_att_done_out_gpios, 0);
	const struct gpio_dt_spec pfr_s0_att_fail =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pfr_s0_att_fail_out_gpios, 0);

	LOG_INF("[PFR->CPLD] PFR_S0_ATT_FAIL De-assert[%s %d]", pfr_s0_att_fail.port->name, pfr_s0_att_fail.pin);
	gpio_pin_configure_dt(&pfr_s0_att_fail, GPIO_OUTPUT);
	gpio_pin_set(pfr_s0_att_fail.port, pfr_s0_att_fail.pin, 0);
	LOG_INF("[PFR->CPLD] PFR_S0_ATT_DONE Assert[%s %d]", pfr_s0_att_done.port->name, pfr_s0_att_done.pin);
	gpio_pin_configure_dt(&pfr_s0_att_done, GPIO_OUTPUT);
	gpio_pin_set(pfr_s0_att_done.port, pfr_s0_att_done.pin, 0);
}

void S0AttestationDone(bool assert)
{
	const struct gpio_dt_spec pfr_s0_att_done =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pfr_s0_att_done_out_gpios, 0);
	const struct gpio_dt_spec pfr_s0_att_fail =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pfr_s0_att_fail_out_gpios, 0);

	if (assert) {
		LOG_INF("[PFR->CPLD] PFR_S0_ATT_FAIL De-assert[%s %d]", pfr_s0_att_fail.port->name, pfr_s0_att_fail.pin);
		gpio_pin_configure_dt(&pfr_s0_att_fail, GPIO_OUTPUT);
		gpio_pin_set(pfr_s0_att_fail.port, pfr_s0_att_fail.pin, 0);
		LOG_INF("[PFR->CPLD] PFR_S0_ATT_DONE Assert[%s %d]", pfr_s0_att_done.port->name, pfr_s0_att_done.pin);
		gpio_pin_configure_dt(&pfr_s0_att_done, GPIO_OUTPUT);
		gpio_pin_set(pfr_s0_att_done.port, pfr_s0_att_done.pin, 1);
	} else {
		LOG_INF("[PFR->CPLD] PFR_S0_ATT_FAIL Assert[%s %d]", pfr_s0_att_fail.port->name, pfr_s0_att_fail.pin);
		gpio_pin_configure_dt(&pfr_s0_att_fail, GPIO_OUTPUT);
		gpio_pin_set(pfr_s0_att_fail.port, pfr_s0_att_fail.pin, 1);
		LOG_INF("[PFR->CPLD] PFR_S0_ATT_DONE De-assert[%s %d]", pfr_s0_att_done.port->name, pfr_s0_att_done.pin);
		gpio_pin_configure_dt(&pfr_s0_att_done, GPIO_OUTPUT);
		gpio_pin_set(pfr_s0_att_done.port, pfr_s0_att_done.pin, 1);
	}
}

void ClearS5Attestation(void)
{
	const struct gpio_dt_spec pfr_s5_att_done =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pfr_s5_att_done_out_gpios, 0);
	const struct gpio_dt_spec pfr_s5_att_fail =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pfr_s5_att_fail_out_gpios, 0);

	LOG_INF("[PFR->CPLD] PFR_S5_ATT_FAIL De-assert[%s %d]", pfr_s5_att_fail.port->name, pfr_s5_att_fail.pin);
	gpio_pin_configure_dt(&pfr_s5_att_fail, GPIO_OUTPUT);
	gpio_pin_set(pfr_s5_att_fail.port, pfr_s5_att_fail.pin, 0);
	LOG_INF("[PFR->CPLD] PFR_S5_ATT_DONE Assert[%s %d]", pfr_s5_att_done.port->name, pfr_s5_att_done.pin);
	gpio_pin_configure_dt(&pfr_s5_att_done, GPIO_OUTPUT);
	gpio_pin_set(pfr_s5_att_done.port, pfr_s5_att_done.pin, 0);
}

void S5AttestationDone(bool assert)
{
	const struct gpio_dt_spec pfr_s5_att_done =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pfr_s5_att_done_out_gpios, 0);
	const struct gpio_dt_spec pfr_s5_att_fail =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pfr_s5_att_fail_out_gpios, 0);
	if (assert) {
		LOG_INF("[PFR->CPLD] PFR_S5_ATT_FAIL De-assert[%s %d]", pfr_s5_att_fail.port->name, pfr_s5_att_fail.pin);
		gpio_pin_configure_dt(&pfr_s5_att_fail, GPIO_OUTPUT);
		gpio_pin_set(pfr_s5_att_fail.port, pfr_s5_att_fail.pin, 0);
		LOG_INF("[PFR->CPLD] PFR_S5_ATT_DONE Assert[%s %d]", pfr_s5_att_done.port->name, pfr_s5_att_done.pin);
		gpio_pin_configure_dt(&pfr_s5_att_done, GPIO_OUTPUT);
		gpio_pin_set(pfr_s5_att_done.port, pfr_s5_att_done.pin, 1);
	} else {
		LOG_INF("[PFR->CPLD] PFR_S5_ATT_FAIL Assert[%s %d]", pfr_s5_att_fail.port->name, pfr_s5_att_fail.pin);
		gpio_pin_configure_dt(&pfr_s5_att_fail, GPIO_OUTPUT);
		gpio_pin_set(pfr_s5_att_fail.port, pfr_s5_att_fail.pin, 1);
		LOG_INF("[PFR->CPLD] PFR_S5_ATT_DONE De-assert[%s %d]", pfr_s5_att_done.port->name, pfr_s5_att_done.pin);
		gpio_pin_configure_dt(&pfr_s5_att_done, GPIO_OUTPUT);
		gpio_pin_set(pfr_s5_att_done.port, pfr_s5_att_done.pin, 1);
	}
}

void ClearBtgAttestation(void)
{
	const struct gpio_dt_spec pfr_btg_att_done =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pfr_btg_att_done_out_gpios, 0);
	const struct gpio_dt_spec pfr_btg_att_fail =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pfr_btg_att_fail_out_gpios, 0);

	LOG_INF("[PFR->CPLD] PFR_BTG_ATT_FAIL De-assert[%s %d]", pfr_btg_att_fail.port->name, pfr_btg_att_fail.pin);
	gpio_pin_configure_dt(&pfr_btg_att_fail, GPIO_OUTPUT);
	gpio_pin_set(pfr_btg_att_fail.port, pfr_btg_att_fail.pin, 0);
	LOG_INF("[PFR->CPLD] PFR_BTG_ATT_DONE Assert[%s %d]", pfr_btg_att_done.port->name, pfr_btg_att_done.pin);
	gpio_pin_configure_dt(&pfr_btg_att_done, GPIO_OUTPUT);
	gpio_pin_set(pfr_btg_att_done.port, pfr_btg_att_done.pin, 0);
}

void BtgAttestationDone(bool assert)
{
	const struct gpio_dt_spec pfr_btg_att_done =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pfr_btg_att_done_out_gpios, 0);
	const struct gpio_dt_spec pfr_btg_att_fail =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), pfr_btg_att_fail_out_gpios, 0);

	if (assert) {
		LOG_INF("[PFR->CPLD] PFR_BTG_ATT_FAIL De-assert[%s %d]", pfr_btg_att_fail.port->name, pfr_btg_att_fail.pin);
		gpio_pin_configure_dt(&pfr_btg_att_fail, GPIO_OUTPUT);
		gpio_pin_set(pfr_btg_att_fail.port, pfr_btg_att_fail.pin, 0);
		LOG_INF("[PFR->CPLD] PFR_BTG_ATT_DONE Assert[%s %d]", pfr_btg_att_done.port->name, pfr_btg_att_done.pin);
		gpio_pin_configure_dt(&pfr_btg_att_done, GPIO_OUTPUT);
		gpio_pin_set(pfr_btg_att_done.port, pfr_btg_att_done.pin, 1);
	} else {
		LOG_INF("[PFR->CPLD] PFR_BTG_ATT_FAIL Assert[%s %d]", pfr_btg_att_fail.port->name, pfr_btg_att_fail.pin);
		gpio_pin_configure_dt(&pfr_btg_att_fail, GPIO_OUTPUT);
		gpio_pin_set(pfr_btg_att_fail.port, pfr_btg_att_fail.pin, 1);
		LOG_INF("[PFR->CPLD] PFR_BTG_ATT_DONE De-assert[%s %d]", pfr_btg_att_done.port->name, pfr_btg_att_done.pin);
		gpio_pin_configure_dt(&pfr_btg_att_done, GPIO_OUTPUT);
		gpio_pin_set(pfr_btg_att_done.port, pfr_btg_att_done.pin, 1);
	}
}

void HPMStandbyReset(bool assert)
{
	const struct gpio_dt_spec hpm_stanby_rst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), hpm_stby_rst_out_gpios, 0);

	LOG_INF("[PFR->CPLD] HPM_STANBY_RST %s[%s %d]",
		assert ? "Assert" : "De-assert",
		hpm_stanby_rst.port->name,
		hpm_stanby_rst.pin);

	gpio_pin_configure_dt(&hpm_stanby_rst, GPIO_OUTPUT);
	gpio_pin_set(hpm_stanby_rst.port, hpm_stanby_rst.pin, assert);
}

void OksRTCRSTControl(bool assert)
{
	const struct gpio_dt_spec rtc_rst_cpu0 =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_oks), rst_rtcrst_cpu0_out_gpios, 0);
	const struct gpio_dt_spec rtc_rst_cpu1 =
		GPIO_DT_SPEC_GET_OR(DT_INST(0, aspeed_pfr_gpio_oks), rst_rtcrst_cpu1_out_gpios, {0});

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
void OksSwitchI3cMng(int owner)
{
	LOG_WRN("I3C Takeover feature is dropped in Oks");
	return;
}
#endif

static void OksPchHold(void)
{
	AUXPowerGoodControl(false);
}

static void OksPchRelease(void)
{
	// Do nothing, pch should be released after CPU_PLTRST_SYNC = 1
	// and BTG attestation done
	LOG_WRN("PCH is not released yet");
	LOG_WRN("Waiting for CPU_PLTRST_SYNC = 1 and BTG attestation done");
}

static const struct platform_gpio_ctrl_ops oks_gpio_ops = {
	.pch_hold = OksPchHold,
	.pch_release = OksPchRelease,
	// .rst_pltrst = OksRSTPlatformReset,
	.rst_rtcrst = OksRTCRSTControl,
#if defined(CONFIG_PFR_MCTP_I3C)
	.i3c_mng_switch = OksSwitchI3cMng,
#endif
};

const struct platform_gpio_ctrl_ops *get_platform_gpio_ctrl_ops(void)
{
	return &oks_gpio_ops;
}

