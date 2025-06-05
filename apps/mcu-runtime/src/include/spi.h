// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
 */

/* Notice, SPI driver operation should be moved to
 * driver layer after SPI driver is finished.
 * After that, normal Zephyr SPI driver should
 * be used.
 */

#ifndef _SPI_AST2700_H
#define _SPI_AST2700_H

#include <stdlib.h>

int spi_init(int id);
int spi_copy(uint32_t *dest, uint32_t src, uint32_t len);
uint32_t fit_ram_load_read(struct fit_load_info *load, uint32_t sector,
			       uint32_t count, void *buf);
#endif
