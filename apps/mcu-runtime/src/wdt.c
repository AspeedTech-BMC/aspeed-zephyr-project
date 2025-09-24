/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <zephyr/kernel.h>
#include <wdt.h>

static void wdt_writel(uint32_t val, uint32_t addr)
{
	sys_write32(val, addr);
	k_busy_wait(5);
}

int wdt_init(struct ast_chip *chip)
{
	uint32_t idx;
	uint32_t wdt_base_addr;

	if (chip->rev_id) {
		/* ast2700a1 */
		for (idx = 0; idx < 8; idx++) {
			wdt_base_addr = ASPEED_WDT_BASE + idx * 0x80;

			/* SoC reset mask */
			wdt_writel(0x8207ff71, wdt_base_addr + WDT_RST_MASK_1);
			wdt_writel(0x000003f6, wdt_base_addr + WDT_RST_MASK_2);
			wdt_writel(0x000093ec, wdt_base_addr + WDT_RST_MASK_3);
			wdt_writel(0x40303803, wdt_base_addr + WDT_RST_MASK_4);
			wdt_writel(0x00320000, wdt_base_addr + WDT_RST_MASK_5);

			/* SW reset mask */
			wdt_writel(0x8207ff71, wdt_base_addr + WDT_SW_RST_MASK_1);
			wdt_writel(0x000003f6, wdt_base_addr + WDT_SW_RST_MASK_2);
			wdt_writel(0x000093ec, wdt_base_addr + WDT_SW_RST_MASK_3);
			wdt_writel(0x40303803, wdt_base_addr + WDT_SW_RST_MASK_4);
			wdt_writel(0x00320000, wdt_base_addr + WDT_SW_RST_MASK_5);
		}
	}

	return 0;
}
