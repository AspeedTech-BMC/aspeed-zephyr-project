/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
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
#include <wdt.h>
#include <extrst.h>
#include <usb.h>

LOG_MODULE_REGISTER(ast_chip, CONFIG_SOC_FMC_LOG_LEVEL);

static struct peripheral peri_tbl[] = {
	{"POLICY",	NULL, NULL},//sys_policy_init},
	{"WDT",		wdt_init, NULL},
	{"EXTRST",	extrst_mask_init, NULL},
	{"LOADER",	ast_loader_init, NULL},
	{"SLI1",	sli_init_f, NULL},
	{"DP",		dp_init, NULL},
	{"SLI0",	sli_init_r, NULL},
	{"DRAM",	dram_init, NULL},
	{"PCI",		pci_init, NULL},
	{"USB",		usb_init, NULL},
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

	/* Put chip info here, for example scu */
	chip->scu0 = (struct ast2700_scu0 *)DT_REG_ADDR(DT_NODELABEL(syscon0));
	chip->scu1 = (struct ast2700_scu1 *)DT_REG_ADDR(DT_NODELABEL(syscon1));
	chip->rev_id = sys_read32(SCU1_CHIP_REV_ID) & CHIP_ID_MASK;
	chip->efuse = FIELD_GET(SCU_CPU_REVISION_ID_EFUSE, sys_read32(SCU0_REVISION_ID));
	chip->pcie0_enable = sys_read32(SCU0_REG + 0xa00) & BIT(0);
	chip->pcie1_enable = sys_read32(SCU0_REG + 0xa80) & BIT(0);

	return chip;
}
