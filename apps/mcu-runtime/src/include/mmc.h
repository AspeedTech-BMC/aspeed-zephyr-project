// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
 */

/* Notice, SPI driver operation should be moved to
 * driver layer after SPI driver is finished.
 * After that, normal Zephyr SPI driver should
 * be used.
 */

#ifndef _MMC_H
#define _MMC_H

#include <stdlib.h>

int mmc_init(int id);
int mmc_copy(uint32_t *dest, uint32_t src, uint32_t len);
uint32_t fit_mmc_load_read(struct fit_load_info *load, uint32_t sector,
			       uint32_t count, void *buf);

#endif
