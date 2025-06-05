/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Aspeed Technology Inc.
 */
#ifndef _ASM_ARCH_SSP_TSP_AST2700_H
#define _ASM_ARCH_SSP_TSP_AST2700_H

#include <zephyr/sys/sys_io.h>

int ssp_init(mem_addr_t load_addr);
int ssp_enable(void);
int tsp_init(mem_addr_t load_addr);
int tsp_enable(void);

#endif
