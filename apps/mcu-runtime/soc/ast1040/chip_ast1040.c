/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <platform.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/logging/log.h>
#include <ast_loader.h>
#include <wdt.h>
#include <extrst.h>

LOG_MODULE_REGISTER(ast_chip, CONFIG_SOC_FMC_LOG_LEVEL);

static struct peripheral peri_tbl[] = {
	{"POLICY",	NULL, NULL},//sys_policy_init},
	{"WDT",		wdt_init, NULL},
	// {"EXTRST",	extrst_mask_init, NULL},
	{"LOADER",	ast_loader_init, NULL},
};

static struct ast_chip ast_1040 = {
	.rev_id = 0,
	.peripheral = peri_tbl,
	.peri_num = ARRAY_SIZE(peri_tbl),
	.board = NULL,
};

struct ast_chip *ast_create_chip(void)
{
	struct ast_chip *chip = &ast_1040;

	/* Put chip info here, for example scu */
	chip->scu0 = NULL;
	chip->scu1 = (void *)DT_REG_ADDR(DT_NODELABEL(syscon1));

	return chip;
}
