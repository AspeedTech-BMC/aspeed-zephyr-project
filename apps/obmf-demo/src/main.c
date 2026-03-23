/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/usb/usb_device.h>
#include "lstp_router.h"
#include "lstp_spi.h"
#include "lstp_task.h"
#include "lstp_usb.h"

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

int main(void)
{
	LOG_INF("Starting obmf-demo application");

	/* Initialize the LSTP framework router */
	lstp_router_init();

	/* Initialize the background hardware task */
	lstp_task_init();

	int ret = lstp_spi_init();
	if (ret != 0) {
		LOG_ERR("Failed to initialize SPI SFDP cache: %d", ret);
	}

	/* Initialize the USB Subsystem for LSTP */
	ret = lstp_usb_init();
	if (ret != 0) {
		LOG_ERR("Failed to initialize USB subsystem: %d", ret);
		return ret;
	}

	LOG_INF("obmf-demo application running");

	/* Main loop: We can suspend or do background tasks here,
	 * as USB operations are handled via callbacks and separate threads.
	 */
	while (1) {
		k_sleep(K_SECONDS(1));
	}

	return 0;
}
