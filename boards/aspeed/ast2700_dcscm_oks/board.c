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

static int ast2700_dcscm_oks_post_init(void)
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
SYS_INIT(ast2700_dcscm_oks_post_init, POST_KERNEL, 60);
