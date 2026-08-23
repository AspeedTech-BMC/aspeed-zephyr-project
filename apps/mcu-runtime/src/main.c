/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <soc.h>
#include <platform.h>
#include <chip.h>
#include <wdt.h>

#include "aspeed_zephyr_project_version.h"

LOG_MODULE_REGISTER(ast_soc_fmc, CONFIG_SOC_FMC_LOG_LEVEL);

int main(void)
{
	struct ast_chip *chip = NULL;
	struct ast_board *board = NULL;
	int err;

	/*
	 * Boot watchdog: it is never fed at mcu-runtime stage, so the SoC
	 * is reset once the timeout expires unless the booted image
	 * disables or takes over wdt0 at u-boot or Linux stage.
	 */
	boot_wdt_enable();

	printf("Aspeed SoC FMC %s %s (%s)\n", CONFIG_BOARD_TARGET, \
		ASPEED_ZEPHYR_PROJECT_VERSION, ASPEED_ZEPHYR_PROJECT_BUILD_TIMESTAMP);

	chip = ast_create_chip();

	if (chip) {
		board = ast_create_board(chip);

		if (board) {
			printf("Trying to boot from %s\n", board->bootmodestr);

			if (board->load_image) {
				err = board->load_image();
				if (err) {
					LOG_ERR("Failed to load image, err=%d", err);
					return err;
				}
			}

			if (board->boot)
				board->boot();

			ast_destroy_chip(chip);
		}
	}

	/* Runtime ipc loop */
	if (board && board->runtime_loop)
		board->runtime_loop();

	return 0;
}
