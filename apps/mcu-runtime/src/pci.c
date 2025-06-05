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
#include <pci_ast2700.h>
#include <scu_ast2700.h>
#include <vga_ast2700.h>

LOG_MODULE_REGISTER(pci, CONFIG_SOC_FMC_LOG_LEVEL);

static void setbits_le32(void *addr, uint32_t set)
{
	sys_write32(sys_read32((uintptr_t)addr) | set, (uintptr_t)addr);
}

int pci_init(void)
{
	struct ast2700_scu0 *scu = (void *)SCU0_REG;
	uint8_t efuse;

	// leave works to u-boot
	if (FIELD_GET(SCU0_REVISION_ID_HW, scu->chip_id1) == 0) {
		LOG_DBG("%s: Do nothing in A0\n", __func__);
		return 0;
	}

	efuse = FIELD_GET(SCU0_REVISION_ID_EFUSE, scu->chip_id1);
	if (efuse == 2) {
		LOG_DBG("%s: 2720 has no PCIE\n", __func__);
		return 0;
	}

	if (efuse == 0) {
		// setup preset for plda2
		sys_write32(0x12600000, ASPEED_PLDA2_PRESET0);
		sys_write32(0x00012600, ASPEED_PLDA2_PRESET1);

		// clk/reset for e2m
		setbits_le32(&scu->clkgate_clr, SCU0_CLKGATE1_E2M1);
		k_msleep(10);
		setbits_le32(&scu->modrst2_clr, SCU0_RST2_E2M1);
	}

	// setup preset for plda1
	sys_write32(0x12600000, ASPEED_PLDA1_PRESET0);
	sys_write32(0x00012600, ASPEED_PLDA1_PRESET1);

	// clk/reset for e2m
	setbits_le32(&scu->clkgate_clr, SCU0_CLKGATE1_E2M0);
	k_msleep(10);
	setbits_le32(&scu->modrst2_clr, SCU0_RST2_E2M0);

	vga_init(scu);

	return 0;
}
