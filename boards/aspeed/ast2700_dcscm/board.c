/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/gpio.h>

LOG_MODULE_REGISTER(board);

static int ast2700_dcscm_post_init(void)
{
	// SMB Mux set to OE_N and Selet 0
	const struct device *dev;
	dev = device_get_binding("gpio0_i_l");
	gpio_pin_configure(dev, 26, GPIO_OUTPUT);
	gpio_pin_set_raw(dev, 26, 0);
	gpio_pin_configure(dev, 27, GPIO_OUTPUT);
	gpio_pin_set_raw(dev, 27, 0);
	return 0;
}

#if defined(CONFIG_DT_HAS_ASPEED_PFR_GPIO_OKS_ENABLED)
extern struct k_event pfr_oks_event;
extern void oks_power_sequence_start(uint32_t events);
extern int oks_s0_attestation(void);
extern int oks_btg_attestation(void);

static int ast2700_dcscm_oks_pwr_seq_handler(void)
{
	oks_power_sequence_start(0);
	LOG_INF("Oks Power Sequence Done");
	while (1) {
		// #define PLATFORM_OKS_FALLBACK               BIT(31)
		// #define PLATFORM_OKS_PLTRST_SYNC_FALLBACK   BIT(30)
		uint32_t events = k_event_wait(&pfr_oks_event, BIT(31) | BIT(30), true, K_FOREVER);
		if (events & BIT(31)) {
			LOG_INF("Oks Power Sequence Fallback");
		} else if (events & BIT(30)) {
			LOG_INF("Oks GLOBAL_RST_SYNC Fallback");
		}
		oks_power_sequence_start(events);
	}
}

K_THREAD_DEFINE(tid, 1024, ast2700_dcscm_oks_pwr_seq_handler, NULL, NULL, NULL, 0, 0, 0);
#else
static int ast2700_dcscm_init(void)
{
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	const struct device *dev;
	dev = device_get_binding("gpio0_e_h");
	gpio_pin_configure(dev, 27, GPIO_OUTPUT_ACTIVE);
#endif
	const struct device *dev;
	dev = device_get_binding("sgpiom_a_d");
	if (dev) {
		LOG_INF("SGPIOM_A_D PIN[3,4,5] to 1");
		gpio_pin_set_raw(dev, 3, 1);	//RES_PFR_BMC_SPI_RESET_N
		gpio_pin_set_raw(dev, 4, 1);	//RST_SPI_PFR_CPU0_RESET_N
		gpio_pin_set_raw(dev, 5, 1);	//RST_SPI_PFR_CPU1_RESET_N
	}

	dev = device_get_binding("sgpiom_e_h");
	if (dev) {
		LOG_INF("SGPIOM_E_H PIN[2,3,4,10,21] to 1");
		gpio_pin_set_raw(dev, 2, 1);	//FP_LED_STATUS_GREEN_N
		gpio_pin_set_raw(dev, 3, 1);	//FP_LED_STATUS_AMBER_N
		gpio_pin_set_raw(dev, 4, 1); 	//RST_PFR_RTCRST_CPU0_N
		gpio_pin_set_raw(dev, 20, 1); 	//RST_PFR_RTCRST_CPU1_N
		gpio_pin_set_raw(dev, 21, 1);	//PWRGD_AUX_PWRGD_PFR_CPU1
	}

	return 0;
}


SYS_INIT(ast2700_dcscm_init, APPLICATION, 0);
#endif
SYS_INIT(ast2700_dcscm_post_init, POST_KERNEL, 60);
