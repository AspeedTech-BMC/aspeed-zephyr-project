/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) ASPEED Technology Inc.
 */

#ifndef _STOR_H
#define _STOR_H

enum boot_mode_type {
	BOOT_DEV_SPI = 0,
	BOOT_DEV_MMC,
	BOOT_DEV_UFS,
	BOOT_DEV_UART,
	BOOT_DEV_USB,
	BOOT_DEV_I2C,
	BOOT_DEV_I3C,
	BOOT_DEV_MAX,
};

enum boot_mode_type boot_mode(void);
#endif
