/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <zephyr/types.h>
#include <zephyr/sys/sys_io.h>
#include <zephyr/sys/util.h>
#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <platform.h>
#include <dp_ast2700.h>
#include <scu_ast2700.h>

LOG_MODULE_REGISTER(dp, CONFIG_SOC_FMC_LOG_LEVEL);

static void setbits_le32(void *addr, uint32_t set)
{
	sys_write32(sys_read32((uintptr_t)addr) | set, (uintptr_t)addr);
}

int dp_init(struct ast_chip *chip)
{
	struct ast2700_scu0 *scu = (void *)SCU0_REG;
	uint32_t mcu_ctrl, val;
	uintptr_t scu_offset;
	bool is_mcu_stop = false;

	val = scu->vga_func_ctrl;
	scu_offset = (((val >> 8) & 0x3) == 1)
		   ? (uintptr_t)&scu->vga1_scratch1[0] : (uintptr_t)&scu->vga0_scratch1[0];
	val = sys_read32(scu_offset);
	is_mcu_stop = ((val & BIT(13)) == 0);

	/* reset for DPTX and DPMCU if MCU isn't running */
	if (is_mcu_stop) {
		LOG_DBG("%s: reset DP & MCU", __func__);
		setbits_le32(&scu->modrst1_ctrl, SCU0_RST_DP);
		setbits_le32(&scu->modrst1_ctrl, SCU0_RST_DPMCU);
		k_usleep(100);

		// enable clk
		setbits_le32(&scu->clkgate_clr, SCU0_CLKGATE1_DP);
		k_msleep(10);

		setbits_le32(&scu->modrst1_clr, SCU0_RST_DP);
		setbits_le32(&scu->modrst1_clr, SCU0_RST_DPMCU);
		k_usleep(1);
	}

	val = sys_read32(DP_VERSION);
	if (val == 0) {
		printf("%s: Can't access DP, version(%x)\n", __func__, val);
		return -1;
	}

	/* select HOST or BMC as display control master
	 * enable or disable sending EDID to Host
	 */
	val = sys_read32(DP_HANDSHAKE);
	val &= ~(DP_HANDSHAKE_HOST_READ_EDID | DP_HANDSHAKE_VIDEO_FMT_SRC);
	sys_write32(val, DP_HANDSHAKE);

	/* DPMCU */
	/* clear display format and enable region */
	sys_write32(0, (MCU_DMEM_BASE + 0x0de0));

	/* load DPMCU firmware to internal instruction memory */
	if (is_mcu_stop) {
		LOG_DBG("%s: DPMCU fw loaded", __func__);
		mcu_ctrl = MCU_CTRL_CONFIG | MCU_CTRL_IMEM_CLK_OFF | MCU_CTRL_IMEM_SHUT_DOWN |
		      MCU_CTRL_DMEM_CLK_OFF | MCU_CTRL_DMEM_SHUT_DOWN | MCU_CTRL_AHBS_SW_RST;
		sys_write32(mcu_ctrl, MCU_CTRL);

		mcu_ctrl &= ~(MCU_CTRL_IMEM_SHUT_DOWN | MCU_CTRL_DMEM_SHUT_DOWN);
		sys_write32(mcu_ctrl, MCU_CTRL);

		mcu_ctrl &= ~(MCU_CTRL_IMEM_CLK_OFF | MCU_CTRL_DMEM_CLK_OFF);
		sys_write32(mcu_ctrl, MCU_CTRL);

		mcu_ctrl |= MCU_CTRL_AHBS_IMEM_EN;
		sys_write32(mcu_ctrl, MCU_CTRL);

		ast_loader_load_image(CPTRA_DP_FW_FW_ID, (uint32_t *)MCU_IMEM_BASE, 0);

		/* release DPMCU internal reset */
		mcu_ctrl &= ~MCU_CTRL_AHBS_IMEM_EN;
		sys_write32(mcu_ctrl, MCU_CTRL);
		mcu_ctrl |= MCU_CTRL_CORE_SW_RST | MCU_CTRL_AHBM_SW_RST;
		sys_write32(mcu_ctrl, MCU_CTRL);
		//disable dp interrupt
		sys_write32(FIELD_PREP(MCU_INTR_CTRL_EN, 0xff), MCU_INTR_CTRL);
	}

	//set vga ASTDP with DPMCU FW handling scratch
	val = sys_read32(scu_offset);
	val &= ~(0x7 << 9);
	val |= 0x7 << 9;
	sys_write32(val, (uintptr_t)&scu->vga0_scratch1[0]);
	sys_write32(val, (uintptr_t)&scu->vga1_scratch1[0]);

	return 0;
}
