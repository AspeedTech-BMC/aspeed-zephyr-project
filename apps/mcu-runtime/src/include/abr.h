/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) ASPEED Technology Inc.
 * Chin-Ting Kuo <chin-ting_kuo@aspeedtech.com>
 *
 */

#ifndef _ABR_H_
#define _ABR_H_

#include <platform.h>

#define ABR_REG                 (SCU1_REG + 0x030)
#define ABR_EN                  BIT(0)
#define ABR_MODE                BIT(29)

bool abr_enabled(void);
uint32_t abr_get_id(void);

#endif
