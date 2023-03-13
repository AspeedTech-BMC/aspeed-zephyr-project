/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <zephyr.h>
#include <build_config.h>
#include <drivers/led.h>

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

#if DT_NODE_EXISTS(DT_NODELABEL(pfr_hb_led_out))
void hbled_tick(struct k_timer *timer_id)
{
	static const struct device *led_dev = NULL;
	static bool tock = false;

	if (led_dev == NULL)
		led_dev = device_get_binding("leds");

	if (led_dev) {
		if (tock) {
			LOG_DBG("PFR_SW_HBLED_OFF");
			led_off(led_dev, 2);
			tock = false;
		} else {
			LOG_DBG("PFR_SW_HBLED_ON");
			led_on(led_dev, 2);
			tock = true;
		}
	}
}

K_TIMER_DEFINE(hbled_timer, hbled_tick, NULL);
#endif

void main(void)
{
	LOG_INF("*** ASPEED_PFR version v%02d.%02d-dev Board:%s ***",
			PROJECT_VERSION_MAJOR, PROJECT_VERSION_MINOR, CONFIG_BOARD);

	aspeed_print_sysrst_info();

#if DT_NODE_EXISTS(DT_NODELABEL(pfr_hb_led_out))
	// Software Heartbeat LED at 1Hz
	k_timer_start(&hbled_timer, K_MSEC(500), K_MSEC(500));
#endif

	AspeedStateMachine();
}
