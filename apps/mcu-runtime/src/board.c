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
#include <scu_ast2700.h>
#include <ssp_tsp_ast2700.h>
#include <manifest.h>
#include <chip.h>

LOG_MODULE_REGISTER(ast_board, CONFIG_SOC_FMC_LOG_LEVEL);

#define ASPEED_UFS_PATH_AXI	(0x12c080e4)

static bool has_pspfw;
static bool has_sspfw;
static bool has_tspfw;

void board_manifest_image_post_process(struct cptra_manifest_ime *ime)
{
	uintptr_t ep = cptra_ime_get_load_addr(ime);
	uint64_t ep_arm = 0;

	/* convert to Arm view */
	ep_arm = ((uint64_t)ep - 0x80000000) | 0x400000000ULL;

	switch (ime->fw_id) {
	case CPTRA_ATF_FW_ID:
		has_pspfw = true;
		sys_write32(ep_arm >> 4, SCU0_CA35_RVBAR0);
		sys_write32(ep_arm >> 4, SCU0_CA35_RVBAR1);
		sys_write32(ep_arm >> 4, SCU0_CA35_RVBAR2);
		sys_write32(ep_arm >> 4, SCU0_CA35_RVBAR3);
		break;
	case CPTRA_UBOOT_FW_ID:
		sys_write64(ep_arm, SCU0_CPU_SMP_EP0);
		break;
	case CPTRA_SSP_FW_ID:
		ssp_init(ep);
		has_sspfw = true;
		break;
	case CPTRA_TSP_FW_ID:
		tsp_init(ep);
		has_tspfw = true;
		break;
	default:
		break;
	}
}

static int board_load_image(void)
{
	int err;

	err = cptra_load_image();

	return err;
}

static void board_prepare_for_boot(void)
{
	/* for v7 FPGA only to switch to uart12. */
	if (IS_ENABLED(CONFIG_ASPEED_FPGA)) {
		sys_write32(SCU0_HWSTRAP_DIS_CPU, SCU0_HW_STRAP1_CLR);
	}

	sys_write32(1, ASPEED_UFS_PATH_AXI);

	if (has_pspfw) {
		/* clean up secondary entries */
		sys_write64(0x0, SCU0_CPU_SMP_EP1);
		sys_write64(0x0, SCU0_CPU_SMP_EP2);
		sys_write64(0x0, SCU0_CPU_SMP_EP3);

		/* release CA35 reset */
		sys_write32(0x1, SCU0_CA35_REL);
	}

	/* release SSP reset */
	if (has_sspfw) {
		ssp_enable();
	}

	/* release TSP reset */
	if (has_tspfw) {
		tsp_enable();
	}
}

static const char *boot_mode_to_string(int bootmode)
{
	switch (bootmode) {
	case BOOT_DEVICE_RAM:
		return "RAM";
	case BOOT_DEVICE_MMC1:
		return "MMC1";
	case BOOT_DEVICE_SATA:
		return "SATA";
	case BOOT_DEVICE_UART:
		return "UART";
	case BOOT_DEVICE_USB:
		return "USB";
	case BOOT_DEVICE_I2C:
		return "I2C";
	case BOOT_DEVICE_I3C:
		return "I3C";
	default:
		return "UNKNOWN";
	}
}

static int board_get_boot_mode(void)
{
	uint32_t dis, strap;

	dis = sys_read32(SCU1_OTPCFG_03_02);
	strap = sys_read32(SCU1_HWSTRAP1);

	/* check if recovery is disabled by OTP */
	if (!(dis & OTPCFG2_DIS_RECOVERY_MODE)) {
		/* check if recovery is enabled by hwstrap */
		if (strap & SCU1_HWSTRAP1_EN_RECOVERY_BOOT) {
			if ((strap & SCU1_HWSTRAP1_RECOVERY_INTERFACE) == SCU1_HWSTRAP1_RECOVERY_USB)
				return BOOT_DEVICE_USB;
			else if ((strap & SCU1_HWSTRAP1_RECOVERY_INTERFACE) == SCU1_HWSTRAP1_RECOVERY_I2C)
				return BOOT_DEVICE_I2C;
			else if ((strap & SCU1_HWSTRAP1_RECOVERY_INTERFACE) == SCU1_HWSTRAP1_RECOVERY_I3C)
				return BOOT_DEVICE_I3C;
			else
				return BOOT_DEVICE_UART;
		}
	}

	if (strap & SCU1_HWSTRAP_EMMC) {
		if (strap & SCU1_HWSTRAP_UFS)
			return BOOT_DEVICE_SATA;
		else
			return BOOT_DEVICE_MMC1;
	} else {
		return BOOT_DEVICE_RAM;
	}
}

static int board_init_f(struct ast_chip	*chip, struct ast_board *board)
{
	struct peripheral *peri_tbl = chip->peripheral;
	int num = chip->peri_num;
	int err = 0;
	int i;

	if (!chip || !board) {
		LOG_ERR("Invalid chip or board pointer.\n");
		return -1;
	}

	chip->bootmode = board_get_boot_mode();
	board->bootmodestr = boot_mode_to_string(chip->bootmode);

	for (i = 0; i < num; i++) {
		if (peri_tbl[i].init) {
			LOG_DBG("%s: %s init", __func__, peri_tbl[i].name);

			err = peri_tbl[i].init(chip);
			if (err)
				LOG_ERR("%s: %s init failed.\n", __func__, peri_tbl[i].name);
		}
	}

	return err;
}

struct ast_board *ast_create_board(struct ast_chip *chip)
{
	struct ast_board *board;
	int err;

	board = malloc(sizeof(struct ast_board));
	if (!board) {
		LOG_ERR("Failed to allocate memory for ast_board");
		return NULL;
	}

	err = board_init_f(chip, board);
	if (err)
		return NULL;

	board->chip = chip;
	board->priv = NULL;
	//board->loader = chip->peripheral[3].priv;
	board->load_image = board_load_image;
	board->boot = board_prepare_for_boot;

	chip->board = board;

	return board;
}
