/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * TODO(AST1080): abr_aspeed driver not ready for the G2 register map yet, so
 * the board builds with CONFIG_ABR_FLOW_CTRL_ASPEED=n. AspeedStateMachine.c
 * calls the ABR API unconditionally (get_boot_indicator/disable_abr_wdt/
 * clear_abr_indicator), so these no-op stubs satisfy the linker WITHOUT
 * modifying the Zephyr BSP. ABR is NON-FUNCTIONAL (always reports primary
 * boot) until a real G2 ABR driver is added; once that driver lands
 * (CONFIG_ABR_FLOW_CTRL_ASPEED=y) this file compiles to nothing.
 */

#include <zephyr/drivers/misc/aspeed/abr_aspeed.h>

#if !defined(CONFIG_ABR_FLOW_CTRL_ASPEED)

enum boot_indicator get_boot_indicator(void)
{
	return BOOT_FROM_PRIMARY_PART;
}

void disable_abr_wdt(void)
{
}

void clear_abr_event_count(void)
{
}

void clear_abr_indicator(void)
{
}

#endif /* !CONFIG_ABR_FLOW_CTRL_ASPEED */
