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

#ifdef CONFIG_ASPEED_HAPS
#define AST2700 0
#define AST1040 1
#define AST27XX  AST1040
static int bootrom_init(struct ast_chip *chip)
{
	uint32_t i;
	uint32_t *rom = (uint32_t *)0x20300000;
	uint32_t ssrom_base[] = {0x14b00000, 0x14c40000};
	uint32_t ssrom_size[] = {0x12000, 0x8000};
	uint32_t base;

	LOG_DBG("bootrom_init\n");

#if defined(AST1040)
	sys_write32(0x0, 0x14c023d4); // map to caliptra ss 0x00000000.
#endif

	base = ssrom_base[AST27XX];

	rom = (uint32_t *) 0x20700000;

	for (i = 0; i < 0x30000/4; i++) {
	      if (i < 8)
		      LOG_INF("bootmcu rom[%d]=0x%x\n", i, rom[i]);

	      sys_write32(rom[i], (0x14b00000 + 4 * i));
	}

	return 0;
}

static struct peripheral peri_tbl[] = {
	{"LOADER",	ast_loader_init, NULL},
	{"BOOTROM",     bootrom_init, NULL},
};
#else
static struct peripheral peri_tbl[] = {
	{"LOADER",	ast_loader_init, NULL},
};
#endif

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

int ast_destroy_chip(struct ast_chip *chip)
{
	int err;

	err = ast_loader_deinit(chip);

	return err;
}
