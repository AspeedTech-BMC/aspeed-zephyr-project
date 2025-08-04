// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
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

LOG_MODULE_REGISTER(ast_soc_fmc, CONFIG_SOC_FMC_LOG_LEVEL);

int main(void)
{
	struct ast_chip *chip = NULL;
	struct ast_board *board = NULL;
	int err;

	printf("Aspeed SoC FMC %s\n", CONFIG_BOARD_TARGET);

	chip = ast_create_chip();

	if (chip) {
		board = ast_create_board(chip);

		if (board) {
			printf("Trying to boot from %s\n", board->bootmodestr);

			err = board->load_image();
			if (err) {
				LOG_ERR("Failed to load image, err=%d", err);
				return err;
			}

			board->boot();

			/* TODO: go to runtime loop */
		}
	}

	return 0;
}
