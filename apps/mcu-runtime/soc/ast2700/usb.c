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
		LOG_DBG("uart%d on usb\n", uart_ports[i]);

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

int usb_init(struct ast_chip *chip)
{
	struct ast2700_scu0 *scu = (void *)SCU0_REG;

	usb_uart_init(chip);

	if (chip->rev_id == 0) {
		LOG_DBG("Do nothing in A0.");
		return 0;
	}

	/* clk/reset for vhuba1 (including PortA 2.0 PHY) */
	setbits_le32(&scu->clkgate_clr, SCU0_CLKGATE1_USBA);
	k_msleep(10);
	setbits_le32(&scu->modrst2_clr, SCU0_RST2_USBA_VHUB);
	k_usleep(1);

	/* Set PortA PHY2 Pre-emphasis current {PHYA_B08} [22:21] = b'10 */
	clrsetbits_le32(ASPEED_VHUBA1_PHY_CTL_3, GENMASK(22, 21), 2 << 21);

	/* clk/reset for vhubb1 (including PortB 2.0 PHY) */
	setbits_le32(&scu->clkgate_clr, SCU0_CLKGATE1_USBB);
	k_msleep(10);
	setbits_le32(&scu->modrst2_clr, SCU0_RST2_USBB_VHUB);
	k_usleep(1);

	/* Set PortB PHY2 Pre-emphasis current {PHYA_B08} [22:21] = b'10 */
	clrsetbits_le32(ASPEED_VHUBB1_PHY_CTL_3, GENMASK(22, 21), 2 << 21);

	return 0;
}