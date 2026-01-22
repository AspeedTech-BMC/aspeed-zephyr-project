/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Notice, SPI driver operation should be moved to
 * driver layer after SPI driver is finished.
 * After that, normal Zephyr SPI driver should
 * be used.
 */

#include <stor.h>
#include <chip.h>

int stor_board_init(struct ast_loader *loader)
{
	int bootmode;
	int err = -1;

	bootmode = loader->bootmode;

	if (bootmode == BOOT_DEVICE_RAM)
		err = spi_register(loader);
	else
		return -1;

	return err;
}
