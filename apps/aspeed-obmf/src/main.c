/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/usb/usb_device.h>
#include "lstp/lstp_router.h"
#include "lstp/lstp_usb.h"

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

int main(void)
{
	LOG_INF("Starting aspeed-obmf application");

	/* Also brings up every exported channel. */
	lstp_router_init();

	int ret = lstp_usb_init();
	if (ret != 0) {
		LOG_ERR("Failed to initialize USB subsystem: %d", ret);
		return ret;
	}

	LOG_INF("aspeed-obmf application running");

	while (1) {
		k_sleep(K_SECONDS(1));
	}

	return 0;
}
