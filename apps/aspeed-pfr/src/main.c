/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <zephyr.h>
#include <build_config.h>
#include <drivers/led.h>
#include <drivers/gpio.h>
#include <drivers/misc/aspeed/abr_aspeed.h>

#include "common/common.h"
#include "include/SmbusMailBoxCom.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_verification.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_verification.h"
#include "cerberus_pfr/cerberus_pfr_provision.h"
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#endif
#include "pfr/pfr_common.h"
#include "AspeedStateMachine/AspeedStateMachine.h"

LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

#define DEBUG_HALT() {				  \
		volatile int halt = 1;		  \
		while (halt) {			  \
			__asm__ volatile ("nop"); \
		}				  \
}

extern void aspeed_print_sysrst_info(void);

#if defined(CONFIG_LED_GPIO)
// TODO: Use DT_NODE_CHILD_IDX to get the index of led devices after upgrade zephyr

#if !DT_NODE_HAS_STATUS(DT_INST(0, gpio_leds), okay)
#error "no correct led gpio device"
#endif

#define LED_LABEL(led_node_id) DT_LABEL(led_node_id),

const char *g_led_child_labels[] = {
	DT_FOREACH_CHILD(DT_INST(0, gpio_leds), LED_LABEL)
};

int g_num_leds = ARRAY_SIZE(g_led_child_labels);

#if DT_NODE_EXISTS(DT_NODELABEL(pfr_hb_led_out))
static uint32_t g_hb_led_inx;

void hbled_tick(struct k_timer *timer_id)
{
	static const struct device *led_dev = NULL;
	static bool tock = false;

	if (led_dev == NULL)
		led_dev = device_get_binding("leds");

	if (led_dev) {
		if (tock) {
			LOG_DBG("PFR_SW_HBLED_OFF");
			led_off(led_dev, g_hb_led_inx);
			tock = false;
		} else {
			LOG_DBG("PFR_SW_HBLED_ON");
			led_on(led_dev, g_hb_led_inx);
			tock = true;
		}
	}
}

K_TIMER_DEFINE(hbled_timer, hbled_tick, NULL);
#endif
#endif

void main(void)
{
	LOG_INF("*** ASPEED_PFR version v%02d.%02d-dev Board:%s ***",
			PROJECT_VERSION_MAJOR, PROJECT_VERSION_MINOR, CONFIG_BOARD);
#if 0
	// Halting for JTAG debug
	disable_abr_wdt();
	DEBUG_HALT();
#endif

	aspeed_print_sysrst_info();

#if defined(CONFIG_LED_GPIO) && DT_NODE_EXISTS(DT_NODELABEL(pfr_hb_led_out))
	for (int i = 0; i < g_num_leds; i++) {
		if (!strcmp(g_led_child_labels[i], "PFR_HB_LED")) {
			// Software Heartbeat LED at 1Hz
			g_hb_led_inx = i;
			LOG_INF("led: start [%s %d]", g_led_child_labels[i], g_hb_led_inx);
			k_timer_start(&hbled_timer, K_MSEC(500), K_MSEC(500));
			break;
		}
	}
#endif

	AspeedStateMachine();
}
