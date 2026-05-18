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
#include <mac_ast2700.h>
#include <ast_loader.h>
#include <wdt.h>
#include <extrst.h>
#include <usb.h>
#include <cptra_idevid.h>

LOG_MODULE_REGISTER(ast_chip, CONFIG_SOC_FMC_LOG_LEVEL);

#ifdef CONFIG_ASPEED_HAPS
#define AST2700 0
#define AST2755 1
#define AST27XX  AST2755
static int bootrom_init(struct ast_chip *chip)
{
	uint32_t i;
	uint32_t *rom = (uint32_t *)0x20300000;
	uint32_t rom_base[] = {0x14b00000, 0x14c40000};
	uint32_t rom_size[] = {0x12000, 0x8000};
	uint32_t base;

	LOG_DBG("bootrom_init\n");

#if defined(AST2755)
	sys_write32(0x0, 0x14c023d8); // map to caliptra ss 0x00000000.
#endif

	base = rom_base[AST27XX];
	for (i = 0; i < rom_size[AST27XX]/4; i++) {
	      if (i < 8)
		      LOG_DBG("rom[%d]=0x%x\n", i, rom[i]);

	      sys_write32(rom[i], (base + 4 * i));
	}

	return 0;
}

static struct peripheral peri_tbl[] = {
	{"POLICY",	NULL, NULL},//sys_policy_init},
	{"WDT",		wdt_init, NULL},
	{"EXTRST",	extrst_mask_init, NULL},
	{"LOADER",	ast_loader_init, NULL},
	{"BOOTROM",     bootrom_init, NULL},
	{"DRAM",	dram_init, NULL},
};
#else
static struct peripheral peri_tbl[] = {
	{"POLICY",	NULL, NULL},//sys_policy_init},
	{"WDT",		wdt_init, NULL},
	{"EXTRST",	extrst_mask_init, NULL},
	{"LOADER",	ast_loader_init, NULL},
	{"SLI1",	sli_init_f, NULL},
	{"DP",		dp_init, NULL},
	{"SLI0",	sli_init_r, NULL},
	{"DRAM",	dram_init, NULL},
	{"USB",		usb_init, NULL},
	{"PCI",		pci_init, NULL},
	{"MAC",		mac_init, NULL},
	{"CPTRA",	cptra_otp_init, NULL},
};
#endif

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

int ast_destroy_chip(struct ast_chip *chip)
{
	int err;

	err = ast_loader_deinit(chip);

	return err;
}
