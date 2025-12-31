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
#include <string.h>

#define AST2700A2 0x2

LOG_MODULE_REGISTER(pci, CONFIG_SOC_FMC_LOG_LEVEL);

#define CHECK_EXIST(node, prop) \
	(strcmp(DT_PROP_OR(node, prop, "None"), "None") ? 1 : 0)

#define PCIE_CONF(node) \
	((CHECK_EXIST(node, vga)        << 0) | \
	 (CHECK_EXIST(node, bmc_device) << 1) | \
	 (CHECK_EXIST(node, ehci)       << 2) | \
	 (CHECK_EXIST(node, xhci)       << 3))

#define CHECK_INTx(node, prop) \
	(strcmp(DT_PROP_OR(node, prop, "INTx"), "MSI") ? 0 : 1)

#define PCIE_INTx(node) \
	((CHECK_INTx(node, vga)        << 0) | \
	 (CHECK_INTx(node, bmc_device) << 1) | \
	 (CHECK_INTx(node, ehci)       << 2) | \
	 (CHECK_INTx(node, xhci)       << 3))

int pci_init(struct ast_chip *chip)
{
	struct ast2700_scu0 *scu = chip->scu0;
	uint8_t pcie0_en = PCIE_CONF(DT_PATH(soc0, pcie0));
	uint8_t pcie1_en = PCIE_CONF(DT_PATH(soc0, pcie1));
	uint8_t pcie0_intx = PCIE_INTx(DT_PATH(soc0, pcie0));
	uint8_t pcie1_intx = PCIE_INTx(DT_PATH(soc0, pcie1));

	sys_write32(pcie0_en * 0x010101 | (pcie0_intx << 24), &scu->pci0_misc[28]);
	sys_write32(pcie1_en * 0x010101 | (pcie1_intx << 24), &scu->pci1_misc[28]);
	LOG_DBG("%s: PCIE0 en=0x%02x int=0x%02x, PCIE1 en=0x%02x int=0x%02x\n", __func__, pcie0_en, pcie0_intx, pcie1_en, pcie1_intx);

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

	/* the raw of e2m need to disable under AST2700 A2 */
	/* turn on vlink codec under AST2700 A2 */
	if (FIELD_GET(SCU0_REVISION_ID_HW, scu->chip_id1) == AST2700A2) {
		setbits_le32(&scu->raw_config, BIT(2)|BIT(13));
		vga_init(chip, true);
	} else {
		vga_init(chip, false);
	}

	return 0;
}
