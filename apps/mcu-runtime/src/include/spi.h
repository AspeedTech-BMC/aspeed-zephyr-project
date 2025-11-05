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

#ifndef _SPI_AST2700_H_
#define _SPI_AST2700_H_

#include <stdlib.h>
#include <ast_loader.h>

#define SPI_SZ_UNSET		0x0
#define SPI_SZ_8MB		0x800000
#define SPI_SZ_16MB		0x1000000
#define SPI_SZ_32MB		0x2000000
#define SPI_SZ_64MB		0x4000000
#define SPI_SZ_128MB		0x8000000
#define SPI_SZ_256MB		0x10000000
#define SPI_SZ_512MB		0x20000000

#endif
