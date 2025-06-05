// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Aspeed Technology Inc.
 */
#include <errno.h>
#include <zephyr/types.h>
#include <zephyr/sys/sys_io.h>
#include <zephyr/sys/util.h>
#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <platform.h>
#include <soc_fmc.h>
#include <fmc_hdr.h>
#include <dp_ast2700.h>
#include <scu_ast2700.h>

LOG_MODULE_REGISTER(dp, CONFIG_SOC_FMC_LOG_LEVEL);

/* Geometry table defines supported timing
 * For each line, the value represents:
 *   0x00: msa's vtotal/htotal
 *   0x04: msa's vstart/hstart
 *   0x08: msa's vactive/hactive
 *   0x0C: msa's vsync/hsync
 */
static uint32_t fw_geometry_table[] = {
	0x020D0320, 0x001B0088, 0x01F00290, 0x00020060,	// 0  656x496@60
	0x02080340, 0x001700A0, 0x01F00290, 0x00030028,	// 1  656x496@72
	0x01F40348, 0x001300B8, 0x01E00280, 0x00030040,	// 2  640x480@75
	0x01FD0340, 0x001C0090, 0x01E00280, 0x00030038,	// 3  640x480@85
	0x02710400, 0x001800C8, 0x02580320, 0x00020048,	// 4  800x600@56
	0x02740420, 0x001B00D8, 0x02580320, 0x00040080,	// 5  800x600@60
	0x029A0410, 0x001D00B8, 0x02580320, 0x00060078,	// 6  800x600@72
	0x02710420, 0x001800F0, 0x02580320, 0x00030050,	// 7  800x600@75
	0x02770418, 0x001E00D8, 0x02580320, 0x00030040,	// 8  800x600@85
	0x03260540, 0x00230128, 0x03000400, 0x00060088,	// 9  1024x768@60
	0x03260530, 0x00230118, 0x03000400, 0x00060088,	// 10 1024x768@70
	0x03200520, 0x001F0110, 0x03000400, 0x00030060,	// 11 1024x768@75
	0x03280560, 0x00270130, 0x03000400, 0x00030060,	// 12 1024x768@85
	0x042A0698, 0x00290168, 0x04000500, 0x00030070,	// 13 1280x1024@60
	0x042A0698, 0x00290188, 0x04000500, 0x00030090,	// 14 1280x1024@75
	0x043006C0, 0x002F0180, 0x04000500, 0x000300A0,	// 15 1280x1024@85
	0x04E20870, 0x003101F0, 0x04B00640, 0x000300C0,	// 16 1600x1200@60
	0x020D0190, 0x001B0038, 0x01F00150, 0x00020030,	// 17 336x496@60
	0x02740210, 0x001B006C, 0x02580190, 0x00040040,	// 18 400x600@60
	0x032602A0, 0x00230094, 0x03000200, 0x00060044,	// 19 512x768@60
	0x04D30820, 0x00200070, 0x04B00780, 0x00060020,	// 20 1920x1200@60
	0x04650898, 0x002900C0, 0x04380780, 0x0005002C,	// 21 1920x1080@60
	0x033F0690, 0x001C0148, 0x03200500, 0x00060080,	// 22 1280x800@60
	0x033705A0, 0x00140070, 0x03200500, 0x00060020,	// 23 1280x800@60
	0x03A60770, 0x001F0180, 0x038405A0, 0x00060098,	// 24 1440x900@60
	0x039E0640, 0x00170070, 0x038405A0, 0x00060020,	// 25 1440x900@60
	0x044108C0, 0x002401C8, 0x041A0690, 0x000600B0,	// 26 1680x1050@60
	0x04380730, 0x001B0070, 0x041A0690, 0x00060020,	// 27 1680x1050@60
	0x03A60840, 0x001F01A8, 0x03840640, 0x000500A8,	// 28 1600x900@60
	0x039E06E0, 0x00170070, 0x03840640, 0x00050020,	// 29 1600x900@60
	0x031B0700, 0x00180170, 0x03000550, 0x00060070,	// 30 1360x768@60
	0x03840640, 0x00230180, 0x03600480, 0x00030080,	// 31 1152x864@60
	0x03E80708, 0x002701A8, 0x03C00500, 0x00030070,	// 32 1280x960@60
	0x01C10190, 0x00030040, 0x019E0150, 0x00020030,
	0x01C10190, 0x00370038, 0x016A0150, 0x00020028,
	0x01C101C2, 0x001B003F, 0x019E017A, 0x0002002D,
	0x01C10320, 0x00030080, 0x019E0290, 0x00020060,
	0x01C10320, 0x00370080, 0x016A0290, 0x00020060,
	0x01C10384, 0x001F0097, 0x019E02E2, 0x0002006C,
	0x01C10190, 0x001B0040, 0x019E0150, 0x00020030,
	0x01C10320, 0x001B0088, 0x019E0290, 0x00020060,
	0x01C10384, 0x00370090, 0x016A02E2, 0x0002006C,
	0x01C10384, 0x001B0090, 0x019E02E2, 0x0002006C,
	0x01C10190, 0x001B0040, 0x019E0150, 0x00020030,
	0x01C10320, 0x001B0088, 0x019E0290, 0x00020060,
	0x01C10320, 0x00370088, 0x016A0290, 0x00020060,
	0x01C10320, 0x00370088, 0x016A0290, 0x00020060,
	0x020D0320, 0x001A0088, 0x01F00290, 0x00020060,
	0x020D0320, 0x001A0088, 0x01F00290, 0x00020060,
	0x01C10320, 0x001B0088, 0x019E0290, 0x00020060,
	0x03E80708, 0x006300B0, 0x03840640, 0x00030050, // 50 1600x900@60
	0x02EE0672, 0x00190104, 0x02D00500, 0x00050028, // 51 1280x720@60
	0x03E80708, 0x002701A8, 0x03C00500, 0x00030070, // 52 1280x960@60
};

static void setbits_le32(void *addr, uint32_t set)
{
	sys_write32(sys_read32((uintptr_t)addr) | set, (uintptr_t)addr);
}

int dp_init(void)
{
	struct ast2700_scu0 *scu = (void *)SCU0_REG;
	uint32_t fw_ofst;
	uint32_t fw_size;
	uint32_t mcu_ctrl, val;
	uintptr_t scu_offset;
	bool is_mcu_stop = false;

	fmc_hdr_get_prebuilt(PBT_DP_FW, &fw_ofst, &fw_size, NULL);
	LOG_DBG("%s: DP-FW addr(%d) size(%d)", __func__, fw_ofst, fw_size);

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

		soc_fmc_obj.stor_copy((uint32_t *)MCU_IMEM_BASE, fw_ofst, fw_size);
		for (int i = 0; i < ARRAY_SIZE(fw_geometry_table); i++)
			sys_write32(fw_geometry_table[i], MCU_DMEM_BASE + (0x900 + (i * 4)));

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
