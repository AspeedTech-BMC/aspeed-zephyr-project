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
#include <usb.h>
#include <wdt.h>
#include <extrst.h>

#define AST2700A2 0x2
#define DISCPUE2M0RAW  BIT(2)
#define DISCPUE2M1RAW  BIT(13)
#define DISIOE2MRAW  BIT(6)

LOG_MODULE_REGISTER(pci, CONFIG_SOC_FMC_LOG_LEVEL);

#define CHECK_EXIST(node, prop) \
	(strcmp(DT_PROP_OR(node, prop, "None"), "None") ? 1 : 0)

#define PCIE_CONF(node) \
	((CHECK_EXIST(node, vga)        << 0) | \
	 (CHECK_EXIST(node, bmc_device) << 1) | \
	 (CHECK_EXIST(node, ehci)       << 2) | \
	 (CHECK_EXIST(node, xhci)       << 3))

#define PCIE_ALT_NODE(node) DT_PROP(node, alt_pcie_node)

#define PCIE_BRIDGE_ALIASING(node) DT_PROP(node, bridge_aliasing)

#define CHECK_INTx(node, prop) \
	(strcmp(DT_PROP_OR(node, prop, "INTx"), "MSI") ? 0 : 1)

#define PCIE_INTx(node) \
	((CHECK_INTx(node, vga)        << 0) | \
	 (CHECK_INTx(node, bmc_device) << 1) | \
	 (CHECK_INTx(node, ehci)       << 2) | \
	 (CHECK_INTx(node, xhci)       << 3))

/**
 * pcie_init_node - Initialize a single PCIe node (PLDA controller)
 * @scu: pointer to SCU0 control register set
 * @node_base: base address of the PLDA node
 * @clk_gate_mask: clock gate enable mask for this node
 * @rst_mask: reset release mask for this node
 *
 * Configures preset values, enables MSI, sets INTA routing, and manages clock/reset
 * sequencing for a single PCIe PLDA node. This API consolidates duplicated node
 * initialization logic for cpu-die (PLDA1/PLDA2) nodes.
 */
static void pcie_init_node(struct ast2700_scu0 *scu,
			   uint32_t node_base,
			   uint32_t clk_gate_mask,
			   uint32_t rst_mask,
			   uint32_t *pci_misc,
			   bool bridge_aliasing)
{
	/* setup preset for plda */
	sys_write32(0x12600000, node_base + PLDA_PRESET0);
	sys_write32(0x00012600, node_base + PLDA_PRESET1);

	/* Enable bridge MSI and set INTA */
	clrbits_le32((void *)(node_base + PLDA_MSI_CAP), BIT(3));
	clrsetbits_le32((void *)(node_base + PLDA_MSI_CAP), GENMASK(2, 0), 0x1);

	if (bridge_aliasing) {
		/* Enable bridge aliasing */
		setbits_le32(&pci_misc[30], BIT(29));
	}

#if !defined(CONFIG_PCIE_ECRC_DISABLE)
	/* Enable ECRC */
	setbits_le32(node_base + PLDA_MISC_48,
		     ECRC_GEN_SUPPORT | ECRC_CHK_SUPPORT);
	setbits_le32(node_base + PLDA_MISC_1FC, ECRC_DISCARD_IF_DS_UNSUPP);
	setbits_le32(node_base + PLDA_MISC_258, ECRC_TX_INSERT_IF_TD);
#endif

	/* clk/reset for e2m */
	setbits_le32(&scu->clkgate_clr, clk_gate_mask);
	k_msleep(10);
	setbits_le32(&scu->modrst2_clr, rst_mask);
}

static void pci_update_xhci_phy_reset_mask(struct ast_chip *chip,
					     uint8_t pcie0_en,
					     uint8_t pcie1_en)
{
	uint32_t xhci_phy_reset_mask = 0;

	/*
	 * usb_init() tentatively marks each port's XHCI-PHY as BMC-owned.
	 * After pcie0/pcie1's "xhci" property (bit3 of PCIE_CONF) is known,
	 * clear the flag for any port whose XHCI is exposed as a PCIe endpoint
	 * (PCIe-XHCI-PHY) instead of used natively by the BMC.
	 */
	chip->usb_porta_bmc_xhci_phy = chip->usb_porta_bmc_xhci_phy && !(pcie0_en & BIT(3));
	chip->usb_portb_bmc_xhci_phy = chip->usb_portb_bmc_xhci_phy && !(pcie1_en & BIT(3));

	/*
	 * Fold only BMC-XHCI-PHY ports into the WDT reset domain (mask2 bit0 =
	 * PortA, bit3 = PortB), so a WDT-triggered SoC reset also resets that
	 * XHCI controller.
	 *
	 * PCIe-XHCI-PHY ports are left untouched since that XHCI controller
	 * belongs to the PCIe host.
	 */
	if (chip->usb_porta_bmc_xhci_phy)
		xhci_phy_reset_mask |= USB_XHCI_PHY_RESET_MASK2_PORTA;
	if (chip->usb_portb_bmc_xhci_phy)
		xhci_phy_reset_mask |= USB_XHCI_PHY_RESET_MASK2_PORTB;

	if (xhci_phy_reset_mask) {
		LOG_DBG("%s: BMC-XHCI-PHY on%s%s, adding to WDT reset mask2\n",
			__func__, chip->usb_porta_bmc_xhci_phy ? " PortA" : "",
			chip->usb_portb_bmc_xhci_phy ? " PortB" : "");
		wdt_config_reset(chip, 1, xhci_phy_reset_mask, xhci_phy_reset_mask);
	}
}

int pci_init(struct ast_chip *chip)
{
	struct ast2700_scu0 *scu = chip->scu0;
	uint8_t pcie0_en = PCIE_CONF(DT_PATH(soc0, pcie0));
	uint8_t pcie1_en = PCIE_CONF(DT_PATH(soc0, pcie1));
	uint8_t pcie0_intx = PCIE_INTx(DT_PATH(soc0, pcie0));
	uint8_t pcie1_intx = PCIE_INTx(DT_PATH(soc0, pcie1));
	uint8_t pcie1_alt = PCIE_ALT_NODE(DT_PATH(soc0, pcie1));
	bool pcie0_bridge_aliasing = PCIE_BRIDGE_ALIASING(DT_PATH(soc0, pcie0));
	bool pcie1_bridge_aliasing = PCIE_BRIDGE_ALIASING(DT_PATH(soc0, pcie1));

	pci_update_xhci_phy_reset_mask(chip, pcie0_en, pcie1_en);

	if ((scu->modrst2_ctrl & (SCU0_RST2_E2M1 | SCU0_RST2_E2M0)) == 0) {
		LOG_DBG("%s: PCIE already initialized\n", __func__);
		return 0;
	}

	scu->pci0_misc[28] = pcie0_en * 0x010101 | (pcie0_intx << 24);
	scu->pci1_misc[28] = pcie1_en * 0x010101 | (pcie1_intx << 24);
	if (pcie1_alt) {
		// disable vga & bmc-dev if alt_pcie_node is set
		clrbits_le32(&scu->pci1_misc[28], 0x03030303);
		clrbits_le32(&scu->pci1_misc[30], BIT(31));
	}
	LOG_DBG("%s: PCIE0 en=0x%02x int=0x%02x, PCIE1 en=0x%02x int=0x%02x\n", __func__, pcie0_en, pcie0_intx, pcie1_en, pcie1_intx);

	// leave works to u-boot
	if (chip->rev_id == 0) {
		LOG_DBG("%s: Do nothing in A0\n", __func__);
		return 0;
	}

	/* cpu-die pcie node 1 */
	pcie_init_node(scu, ASPEED_PLDA2_BASE,
		       SCU0_CLKGATE1_E2M1, SCU0_RST2_E2M1,
		       scu->pci1_misc, pcie1_bridge_aliasing);

	/* cpu-die pcie node 0 */
	pcie_init_node(scu, ASPEED_PLDA1_BASE,
		       SCU0_CLKGATE1_E2M0, SCU0_RST2_E2M0,
		       scu->pci0_misc, pcie0_bridge_aliasing);

	/* io-die pcie node */
	// Enable Bridge3 MSI
	clrbits_le32((void *)(ASPEED_PLDA3_BASE + PLDA_MSI_CAP), BIT(3));
	// Set Bridge3 INTA
	clrsetbits_le32((void *)(ASPEED_PLDA3_BASE + PLDA_MSI_CAP), GENMASK(2, 0), 0x1);
	// Assert E2M reset
	setbits_le32(&scu->modrst2_ctrl, SCU1_RSTCTL2_E2M);
	k_msleep(10);
	// Deassert E2M reset
	setbits_le32(&scu->modrst2_clr, SCU1_RSTCTL2_E2M);
	k_msleep(10);

	/* the raw of e2m need to disable under AST2700 A2 CPU / IO die */
	/* turn on vlink codec under AST2700 A2 */
	if (FIELD_GET(SCU0_REVISION_ID_HW, scu->chip_id1) == AST2700A2) {
		setbits_le32(&scu->raw_config, DISCPUE2M0RAW|DISCPUE2M1RAW);
		setbits_le32(SCU1_RAW_CONFIG, DISIOE2MRAW);

		vga_init(chip, true);
	} else {
		vga_init(chip, false);
	}

	return 0;
}
