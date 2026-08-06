/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ASPEED_WDT_H_
#define _ASPEED_WDT_H_

#include <chip.h>

#define RELOAD_VAL		0x04
#define COUNTER_RESTART		0x08
#define WDT_CTRL		0x0c

#define WDT_RST_MASK_1		0x1c
#define WDT_RST_MASK_2		0x20
#define WDT_RST_MASK_3		0x24
#define WDT_RST_MASK_4		0x28
#define WDT_RST_MASK_5		0x2c

#define WDT_SW_RST_MASK_1	0x34
#define WDT_SW_RST_MASK_2	0x38
#define WDT_SW_RST_MASK_3	0x3c
#define WDT_SW_RST_MASK_4	0x40
#define WDT_SW_RST_MASK_5	0x44

#define WDT_ABR_CTRL		0x4c
#define WDT_ABR_INDICATOR	BIT(1)

#define RESET_WDT_BY_SOC_RESET	BIT(4)
#define RESET_SYS_AFTER_TIMEOUT	BIT(1)
#define WDT_ENABLE		BIT(0)

int wdt_init(struct ast_chip *chip);
int wdt_config_reset(struct ast_chip *chip, uint32_t mask_idx,
		     uint32_t mask, uint32_t value);
#endif
