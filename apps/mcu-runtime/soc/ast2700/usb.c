/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/types.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <platform.h>
#include <scu.h>
#include <usb.h>
#include <ast_loader.h>

LOG_MODULE_REGISTER(usb, CONFIG_SOC_FMC_LOG_LEVEL);

enum usb_port {
	PORT_A,
	PORT_B,
};

enum scu0_usb_function {
	NOT_USED,
	EHCI_VHUB_AND_XHCI_PHY,
	XHCI_PHY,
	XHCI_VHUB,
	EHCI_VHUB,
	VHUB_PHY,
	EHCI_PHY,
};

#define USB_A DT_NODELABEL(usb0)
#define USB_B DT_NODELABEL(usb1)


#define BEHCI_PRE_EOF1_MASK	GENMASK(21, 12)
#define BEHCI_PRE_EOF2_MASK	GENMASK(31, 22)

#define BEHCI_PRE_EOF1(x)	FIELD_PREP(BEHCI_PRE_EOF1_MASK, (x))
#define BEHCI_PRE_EOF2(x)	FIELD_PREP(BEHCI_PRE_EOF2_MASK, (x))

/*
 * Workaround: set preEOF1 to 0x100 and preEOF2 to preEOF1 + MPS.
 * Use MPS 0x40 for the current configuration.
 */
#define BEHCI_PRE_EOF1_VAL	0x100
#define BEHCI_WORKAROUND_MPS	0x40

#define BEHCI_EOF1_EOF2_TIMING \
	(BEHCI_PRE_EOF1(BEHCI_PRE_EOF1_VAL) | \
	 BEHCI_PRE_EOF2(BEHCI_PRE_EOF1_VAL + BEHCI_WORKAROUND_MPS))

#define PHY3P00_DEFAULT		0xCE70000F	/* PHY PCS Protocol Setting #1 default value */
#define PHY3P04_DEFAULT		0x49C00014	/* PHY PCS Protocol Setting #2 default value */
#define PHY3P08_DEFAULT		0x5E406825	/* PHY PCS Protocol Setting #3 default value */
#define PHY3P0C_DEFAULT		0x00000001	/* PHY PCS Protocol Setting #4 default value */

#define DWC_CRTL_NUM		3
#define BURST_128		0x00000006
#define BURST_256		0x0000000E
#define DEFAULT_BURST_SIZE	BURST_128

#define USB_PHY3_INIT_DONE	BIT(15)	/* BIT15: USB3.1 Phy internal SRAM initialization done */
#define USB_PHY3_SRAM_BYPASS	BIT(7)	/* USB3.1 Phy SRAM bypass */
#define USB_PHY3_SRAM_EXT_LOAD	BIT(6)	/* USB3.1 Phy SRAM external load done */

struct usb_dwc3_ctrl {
	uint32_t offset;
	uint32_t value;
};

static struct usb_dwc3_ctrl ctrl_data[DWC_CRTL_NUM] = {
	{0xc100, DEFAULT_BURST_SIZE},	/* Set DWC3 GSBUSCFG0 for Bus Burst Type */
	{0xc12c, 0x0c854802},		/* Set DWC3 GUCTL for ref_clk */
	{0xc630, 0x0c800020},		/* Set DWC3 GLADJ for ref_clk */
};
static bool phy_ext_load_quirk = false;

static int _parse_ports(const char *config_str, uint32_t *ports, int max_ports)
{
	char *token;
	char *str = malloc(strlen(config_str) + 1);
	int num_ports = 0;

        if (str == NULL) {
                LOG_ERR("Memory allocation failed");
                return 0;
        }

        strcpy(str, config_str);
	token = strtok(str, ",");
	while (token != NULL && num_ports < max_ports) {
		ports[num_ports++] = atoi(token);
		token = strtok(NULL, ",");
	}
	free(str);
	return num_ports;
}

static int usb_uart_init(struct ast_chip *chip)
{
#ifdef CONFIG_USB_UART_PORTS
	struct ast2700_scu1 *scu = (void *)SCU1_REG;
	uint32_t reg = AST_VHUBC_BASE + AST_USB_UART_CTRL0;
	uint32_t uart_ports[AST_UDC_MAX_NUM_UART_PORTS], port;
	int i = 0, num_ports;
	uint32_t mode_sel = 0, dev_en = 0;
	const char *config_str = CONFIG_USB_UART_PORTS;

	num_ports = _parse_ports(config_str, uart_ports, AST_UDC_MAX_NUM_UART_PORTS);
	if (num_ports == 0) {
		LOG_DBG("No valid UART ports found in configuration");
		return 0;
	}

	setbits_le32(&scu->clkgate_clr2, SCU1_CLKGATE2_USB2C);
	k_msleep(10);
	setbits_le32(&scu->modrst2_clr, SCU1_RSTCTL2_USB2C);
	k_usleep(1);

	// Clear USB_CTRL[1:0] to enable vHub + USB2UART on portc
	clrbits_le32(&scu->usb_ctrl, 0x3);

	// Control which uart ports to enable on usb2uart
	dev_en = sys_read32(reg + AST_USB_COM_EN_CTRL);

	for (i = 0; i < num_ports; i++) {
		// io-die uart only
		if (uart_ports[i] == 4 || uart_ports[i] > AST_UDC_MAX_NUM_UART_PORTS) {
			LOG_WRN("Ignoring invalid UART port %d", uart_ports[i]);
			continue;
		}
		LOG_DBG("uart%d on usb", uart_ports[i]);

		if (uart_ports[i] < 4)
			port = uart_ports[i];
		else
			port = uart_ports[i] - 1;

		mode_sel |= (0x2 << (port * 2));
		dev_en |= BIT(port + 16);
	}

	LOG_INF("Enabled UART ports");

	sys_write32(mode_sel, reg + AST_USB_COM_MODE_SEL);
	sys_write32(dev_en, reg + AST_USB_COM_EN_CTRL);
#endif

	return 0;
}

static int usb_usb3_init(struct ast_chip *chip, enum usb_port port)
{
	struct ast2700_scu0 *scu = chip->scu0;
	bool large_burst;
	uint32_t phy3_reg, clk, rst;
	uint32_t val;
	uint32_t timeout = 100;
	uint32_t i, offset;

	if (port == PORT_A) {
		phy3_reg = DT_REG_ADDR_BY_NAME(USB_A, phy3);
		clk = SCU0_CLKGATE1_USBA;
		rst = SCU0_RST2_USBA_PHY3 | SCU0_RST2_USBA_XHCI;
		large_burst = DT_PROP(USB_A, enable_large_burst);

	} else if (port == PORT_B) {
		phy3_reg = DT_REG_ADDR_BY_NAME(USB_B, phy3);
		clk = SCU0_CLKGATE1_USBB;
		rst = SCU0_RST2_USBB_PHY3 | SCU0_RST2_USBB_XHCI;
		large_burst = DT_PROP(USB_B, enable_large_burst);
	}

	/* Clk/Reset for USB PHY3 and XHCI controllers */
	setbits_le32(&scu->clkgate_clr, clk);
	k_msleep(10);
	setbits_le32(&scu->modrst2_clr, rst);
	k_usleep(1);

	while ((sys_read32(phy3_reg + ASPEED_USB_PHY3_S00) & USB_PHY3_INIT_DONE) !=
	        USB_PHY3_INIT_DONE) {
		k_usleep(100);
		if (--timeout == 0) {
			LOG_ERR("Wait phy3 init timed out");
			return -ETIMEDOUT;
		}
	}

	val = sys_read32(phy3_reg + ASPEED_USB_PHY3_S00);

	if (phy_ext_load_quirk)
		val |= USB_PHY3_SRAM_EXT_LOAD;
	else
		val |= USB_PHY3_SRAM_BYPASS;
	sys_write32(val, phy3_reg + ASPEED_USB_PHY3_S00);

	/* Set protocol1_ext signals as default PHY3 settings based on SNPS documents.
	 * Including PCFGI[54]: protocol1_ext_rx_los_lfps_en for better compatibility
	 */
	sys_write32(PHY3P00_DEFAULT, phy3_reg + ASPEED_USB_PHY3_P00);
	sys_write32(PHY3P04_DEFAULT, phy3_reg + ASPEED_USB_PHY3_P04);
	sys_write32(PHY3P08_DEFAULT, phy3_reg + ASPEED_USB_PHY3_P08);
	sys_write32(PHY3P0C_DEFAULT, phy3_reg + ASPEED_USB_PHY3_P0C);

	/* Set XHCI bus burst size according to PCIe max. payload size is 512/256 or 128 */
	if (large_burst)
		ctrl_data[0].value = BURST_256;
	else
		ctrl_data[0].value = BURST_128;

	/* xHCI DWC specific command initially set when PCIe xHCI enable */
	for (i = 0, offset = ASPEED_USB_PHY3_DWC; i < DWC_CRTL_NUM; i++) {
		/* 48-bits Command:
		 * CMD1: Data -> DWC CMD [31:0], Address -> DWC CMD [47:32]
		 * CMD2: Data -> DWC CMD [79:48], Address -> DWC CMD [95:80]
		 * ... and etc.
		 */
		if (i % 2 == 0) {
			sys_write32(ctrl_data[i].value, phy3_reg + offset);
			offset += 4;

			sys_write32(ctrl_data[i].offset & 0xFFFF, phy3_reg + offset);
		} else {
			val = sys_read32(phy3_reg + offset) & 0xFFFF;
			val |= ((ctrl_data[i].value & 0xFFFF) << 16);
			sys_write32(val, phy3_reg + offset);
			offset += 4;

			val = (ctrl_data[i].offset << 16) | (ctrl_data[i].value >> 16);
			sys_write32(val, phy3_reg + offset);
			offset += 4;
		}
	}

	LOG_DBG("Initialized %s USB3 %s", port == PORT_A ? "PortA" : "PortB",
		large_burst ? "(Large Burst)" : "");
	return 0;
}
static bool usb_func_has_ehci(enum scu0_usb_function func)
{
	switch (func) {
	case EHCI_VHUB_AND_XHCI_PHY:
	case EHCI_VHUB:
	case EHCI_PHY:
		return true;
	default:
		return false;
	}
}

static bool usb_func_has_xhci_phy(enum scu0_usb_function func)
{
	switch (func) {
	case EHCI_VHUB_AND_XHCI_PHY:
	case XHCI_PHY:
		return true;
	default:
		return false;
	}
}
static int usb_usb2_init(struct ast_chip *chip, enum usb_port port, enum scu0_usb_function func)
{
	struct ast2700_scu0 *scu = chip->scu0;
	uint32_t phy2_reg, ehci_reg, clk, rst;
	bool has_ehci = usb_func_has_ehci(func);

	if (port == PORT_A) {
		phy2_reg = DT_REG_ADDR_BY_NAME(USB_A, phy2);
		ehci_reg = DT_REG_ADDR_BY_NAME(USB_A, ehci);
		clk = SCU0_CLKGATE1_USBA;
		rst = SCU0_RST2_USBA_VHUB1;
		if (has_ehci)
			rst |= SCU0_RST2_USBA_EHCI_VHUB0;
	} else if (port == PORT_B) {
		phy2_reg = DT_REG_ADDR_BY_NAME(USB_B, phy2);
		ehci_reg = DT_REG_ADDR_BY_NAME(USB_B, ehci);
		clk = SCU0_CLKGATE1_USBB;
		rst = SCU0_RST2_USBB_VHUB1;
		if (has_ehci)
			rst |= SCU0_RST2_USBB_EHCI_VHUB0;
	}

	/* Clk/Reset for EHCI/vHUB1 (Port 2.0 PHY) */
	setbits_le32(&scu->clkgate_clr, clk);
	k_msleep(10);
	setbits_le32(&scu->modrst2_clr, rst);
	k_usleep(1);

	/* Set PortA/B PHY2 (inside vHUB1) {PHYA_B04} [27:26] = b'11: xHCI to vHub1 clock rate as 60MHz */
	clrsetbits_le32((phy2_reg + ASPEED_USB_PHY_CTL_STS_2), GENMASK(27, 26), 3 << 26);

	/* Set PortA/B PHY2 (inside vHUB1) {PHYA_B08} [22:21] = b'10: Pre-emphasis current setting to 2 */
	clrsetbits_le32((phy2_reg + ASPEED_USB_PHY_CTL_STS_3), GENMASK(22, 21), 2 << 21);

	/* Set PortA/B EHCI {BEHCI88: Frame Timing Adjustment} EOF1/EOF2 timing to workaround the DMA termination bug. */
	if (has_ehci)
		sys_write32(BEHCI_EOF1_EOF2_TIMING, (ehci_reg + ASPEED_USB_BEHCI_FRM_TIMING));

	LOG_DBG("Initialized %s USB2", port == PORT_A ? "PortA" : "PortB");
	return 0;
}
static void usb_func_init(struct ast_chip *chip, enum usb_port port,
			  enum scu0_usb_function func)
{
	struct ast2700_scu0 *scu = chip->scu0;
	uint32_t vhub_ehci_shift, u3_xhci_shift, u2_xhci_shift;

	switch (port) {
	case PORT_A:
		vhub_ehci_shift = 24;
		u3_xhci_shift = 0;
		u2_xhci_shift = 2;
		break;
	case PORT_B:
		vhub_ehci_shift = 28;
		u3_xhci_shift = 4;
		u2_xhci_shift = 6;
		break;
	default:
		return;
	}

	switch (func) {
	case EHCI_VHUB:
		/* EHCI to vHUB */
		clrsetbits_le32(&scu->usb_func_ctrl,
				GENMASK(vhub_ehci_shift + 1, vhub_ehci_shift),
				0 << vhub_ehci_shift);
		break;

	case EHCI_VHUB_AND_XHCI_PHY:
	case XHCI_PHY:
		/* EHCI to vHUB */
		clrsetbits_le32(&scu->usb_func_ctrl,
				GENMASK(vhub_ehci_shift + 1, vhub_ehci_shift),
				0 << vhub_ehci_shift);

		/* XHCI to PHY */
		clrsetbits_le32(&scu->usb_func_ctrl,
				GENMASK(u3_xhci_shift + 1, u3_xhci_shift),
				2 << u3_xhci_shift);
		clrsetbits_le32(&scu->usb_func_ctrl,
				GENMASK(u2_xhci_shift + 1, u2_xhci_shift),
				2 << u2_xhci_shift);
		break;

	case VHUB_PHY:
		/* vHUB1 to PHY */
		clrsetbits_le32(&scu->usb_func_ctrl,
				GENMASK(u2_xhci_shift + 1, u2_xhci_shift),
				1 << u2_xhci_shift);
		clrsetbits_le32(&scu->usb_func_ctrl,
				GENMASK(vhub_ehci_shift + 1, vhub_ehci_shift),
				0 << vhub_ehci_shift);
		break;

	case EHCI_PHY:
		/* PCIe EHCI to PHY */
		clrsetbits_le32(&scu->usb_func_ctrl,
				GENMASK(vhub_ehci_shift + 1, vhub_ehci_shift),
				3 << vhub_ehci_shift);
		break;

	case XHCI_VHUB:
		/* XHCI to vHUB */
		clrsetbits_le32(&scu->usb_func_ctrl,
				GENMASK(u3_xhci_shift + 1, u3_xhci_shift),
				2 << u3_xhci_shift);
		clrsetbits_le32(&scu->usb_func_ctrl,
				GENMASK(u2_xhci_shift + 1, u2_xhci_shift),
				0 << u2_xhci_shift);
		clrsetbits_le32(&scu->usb_func_ctrl,
				GENMASK(vhub_ehci_shift + 1, vhub_ehci_shift),
				0 << vhub_ehci_shift);
		break;

	default:
		break;
	}
}

static int usb_port_init(struct ast_chip *chip, enum usb_port port,
			 enum scu0_usb_function func)
{
	int ret;

	switch (func) {
	case EHCI_VHUB_AND_XHCI_PHY:
	case XHCI_PHY:
	case XHCI_VHUB:
		/* Initialize USB PHY3 and XHCI controllers */
		ret = usb_usb3_init(chip, port);
		if (ret)
			return ret;
		/* fall through */

	case EHCI_VHUB:
	case VHUB_PHY:
	case EHCI_PHY:
		/* Initialize USB2 EHCI and vHUB (also PHY2) controllers */
		ret = usb_usb2_init(chip, port, func);
		if (ret)
			return ret;
		break;

	default:
		break;
	}

	return 0;
}
int usb_init(struct ast_chip *chip)
{
	struct ast2700_scu0 *scu = chip->scu0;
	enum scu0_usb_function porta_func =
		DT_ENUM_IDX_OR(USB_A, usb_function, EHCI_VHUB_AND_XHCI_PHY);
	enum scu0_usb_function portb_func =
		DT_ENUM_IDX_OR(USB_B, usb_function, EHCI_VHUB_AND_XHCI_PHY);
	char* func_string [] = {
		"NOT_USED",
		"EHCI_VHUB & XHCI_PHY",
		"XHCI_PHY",
		"XHCI_VHUB",
		"EHCI_VHUB",
		"VHUB_PHY",
		"EHCI_PHY",
	};
	int ret;

	usb_uart_init(chip);

	if (chip->rev_id == 0) {
		LOG_DBG("Do nothing in A0.");
		return 0;
	}

	if (chip->bootmode == BOOT_DEVICE_USB) {
		int port = FIELD_GET(SCU1_HWSTRAP1_RECOVERY_USB_PORT, sys_read32(SCU1_HWSTRAP1));
		LOG_INF("USB Recovery Mode: Port = %d", port);
		if (port == 0)
			porta_func = VHUB_PHY;
		else if (port == 1)
			portb_func = VHUB_PHY;
	}

	/*
	 * Record whether each port's XHCI-PHY is tentatively BMC-owned.
	 * pci_init() will clear the flag for any port whose XHCI is actually
	 * exposed as a PCIe endpoint (PCIe-XHCI-PHY).
	 */
	chip->usb_porta_bmc_xhci_phy = usb_func_has_xhci_phy(porta_func);
	chip->usb_portb_bmc_xhci_phy = usb_func_has_xhci_phy(portb_func);

	/* Switch PortA and PortB USB function */
	usb_func_init(chip, PORT_A, porta_func);
	usb_func_init(chip, PORT_B, portb_func);
	LOG_INF("A = %s, B = %s (0X%08X)",
		func_string[porta_func], func_string[portb_func], readl(&scu->usb_func_ctrl));

	ret = usb_port_init(chip, PORT_A, porta_func);
	if (ret)
		return ret;

	ret = usb_port_init(chip, PORT_B, portb_func);
	if (ret)
		return ret;

	return 0;
}
