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
#include <pci_ast2700.h>
#include <scu.h>
#include <vga_ast2700.h>
#include <ast_loader.h>

LOG_MODULE_REGISTER(pci, CONFIG_SOC_FMC_LOG_LEVEL);

int pci_init(struct ast_chip *chip)
{
	struct ast2700_scu0 *scu = chip->scu0;

	// leave works to u-boot
	if (chip->rev_id == 0) {
		LOG_DBG("%s: Do nothing in A0\n", __func__);
		return 0;
	}

	/* cpu-die pcie node 1 */
	// setup preset for plda2
	sys_write32(0x12600000, ASPEED_PLDA2_PRESET0);
	sys_write32(0x00012600, ASPEED_PLDA2_PRESET1);

	// Enable Bridge2 MSI
	clrbits_le32((void *)ASPEED_PLDA2_MSI_CAP, BIT(3));
	// Set Bridge2 INTA
	clrsetbits_le32((void *)ASPEED_PLDA2_MSI_CAP, GENMASK(2, 0), 0x1);

	// clk/reset for e2m
	setbits_le32(&scu->clkgate_clr, SCU0_CLKGATE1_E2M1);
	k_msleep(10);
	setbits_le32(&scu->modrst2_clr, SCU0_RST2_E2M1);

	/* cpu-die pcie node 0 */
	// setup preset for plda1
	sys_write32(0x12600000, ASPEED_PLDA1_PRESET0);
	sys_write32(0x00012600, ASPEED_PLDA1_PRESET1);

	// Enable Bridge1 MSI
	clrbits_le32((void *)ASPEED_PLDA1_MSI_CAP, BIT(3));
	// Set Bridge1 INTA
	clrsetbits_le32((void *)ASPEED_PLDA1_MSI_CAP, GENMASK(2, 0), 0x1);

	// clk/reset for e2m
	setbits_le32(&scu->clkgate_clr, SCU0_CLKGATE1_E2M0);
	k_msleep(10);
	setbits_le32(&scu->modrst2_clr, SCU0_RST2_E2M0);

	/* io-die pcie node */
	// Enable Bridge3 MSI
	clrbits_le32((void *)ASPEED_PLDA3_MSI_CAP, BIT(3));
	// Set Bridge3 INTA
	clrsetbits_le32((void *)ASPEED_PLDA3_MSI_CAP, GENMASK(2, 0), 0x1);

	vga_init(chip);

	return 0;
}
