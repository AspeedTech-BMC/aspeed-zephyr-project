/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ASM_ARCH_SSP_TSP_H
#define _ASM_ARCH_SSP_TSP_H

#include <zephyr/sys/sys_io.h>

int ssp_init(mem_addr_t load_addr);
int ssp_enable(void);
int tsp_init(mem_addr_t load_addr);
int tsp_enable(void);

#endif
