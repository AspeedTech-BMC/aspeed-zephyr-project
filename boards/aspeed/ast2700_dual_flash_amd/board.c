/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(board);

/* Reserved for platform specific operation */
static int ast2700_dual_flash_amd_post_init(void)
{
	return 0;
}

static int ast2700_dual_flash_amd_init(void)
{
	return 0;
}

SYS_INIT(ast2700_dual_flash_amd_init, APPLICATION, 0);
SYS_INIT(ast2700_dual_flash_amd_post_init, POST_KERNEL, 60);
