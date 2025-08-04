// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) ASPEED Technology Inc.
 */

#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/logging/log.h>
#include <sli.h>
#include <vga_ast2700.h>
#include <scu_ast2700.h>
#include <sdram_ast2700.h>
#include <dp_ast2700.h>
#include <pci_ast2700.h>
#include <ast_loader.h>

LOG_MODULE_REGISTER(ast_chip, CONFIG_SOC_FMC_LOG_LEVEL);

static struct peripheral peri_tbl[] = {
	{"POLICY",	NULL, NULL},//sys_policy_init},
	{"WDT",		NULL, NULL},//wdt_init},
	{"EXTRST",	NULL, NULL},//extrst_mask_init},
	{"LOADER",	ast_loader_init, NULL},
	{"SLI1",	sli_init_f, NULL},
	{"DP",		dp_init, NULL},
	{"SLI0",	sli_init_r, NULL},
	{"DRAM",	dram_init, NULL},
	{"PCI",		pci_init, NULL},
};

static struct ast_chip ast_27xx = {
	.rev_id = 0,
	.peripheral = peri_tbl,
	.peri_num = ARRAY_SIZE(peri_tbl),
	.board = NULL,
};

struct ast_chip *ast_create_chip(void)
{
	struct ast_chip *chip = &ast_27xx;

	/* en low secure for uartdbg */
	sys_write32(0x100, 0x14c02010);

	chip->rev_id = sys_read32(SCU1_CHIP_REV_ID) & CHIP_ID_MASK;

	/* Put chip info here, for example scu */

	return chip;
}
