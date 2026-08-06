/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _USB_H
#define _USB_H

#include <chip.h>

#define ASPEED_UPHY3A_BASE              0x12010000
#define ASPEED_UPHY3B_BASE              0x12020000
#define  ASPEED_USB_PHY3_S00            0x00    /* PHY SRAM Control/Status #1 */
#define  ASPEED_USB_PHY3_S04            0x04    /* PHY SRAM Control/Status #2 */
#define  ASPEED_USB_PHY3_C00            0x08    /* PHY PCS Control/Status #1 */
#define  ASPEED_USB_PHY3_C04            0x0C	/* PHY PCS Control/Status #2 */
#define  ASPEED_USB_PHY3_P00            0x10	/* PHY PCS Protocol Setting #1 */
#define  ASPEED_USB_PHY3_P04            0x14	/* PHY PCS Protocol Setting #2 */
#define  ASPEED_USB_PHY3_P08            0x18	/* PHY PCS Protocol Setting #3 */
#define  ASPEED_USB_PHY3_P0C            0x1C	/* PHY PCS Protocol Setting #4 */
#define  ASPEED_USB_PHY3_DWC            0x40	/* DWC3 Commands base address offest */

#define ASPEED_VHUBA0_BASE              0x12060000
#define ASPEED_VHUBB0_BASE              0x12062000
#define ASPEED_VHUBA1_BASE              0x12011000
#define ASPEED_VHUBB1_BASE              0x12021000
#define  ASPEED_USB_PHY_CTL_STS_1        0x800 /* USB PHY Control/Status #1 */
#define  ASPEED_USB_PHY_CTL_STS_2        0x804 /* USB PHY Control/Status #2 */
#define  ASPEED_USB_PHY_CTL_STS_3        0x808 /* USB PHY Control/Status #3 */
#define  ASPEED_USB_PHY_CTL_STS_4        0x80C /* USB PHY Control/Status #4 */

#define ASPEED_BEHCI0_BASE              0x12061800
#define ASPEED_BEHCI1_BASE              0x12063800
#define  ASPEED_USB_BEHCI_FRM_TIMING     0x88 /* Frame Timing Adjustment */

#define AST_VHUBC_BASE			(0x14120000)
#define AST_USB_UART_CTRL0		0x800
#define  AST_USB_COM_MODE_SEL		0x10
#define  AST_USB_COM_EN_CTRL		0x1C

#define AST_UDC_MAX_NUM_UART_PORTS	15

/*
 * WDT "mask2" reset-domain bits gate whether a WDT-triggered SoC reset also
 * resets the port's XHCI-PHY.
 *
 * Only BMC-XHCI-PHY ports are asserted; PCIe-XHCI-PHY ports must stay out of
 * this reset domain since the PCIe host owns that XHCI controller.
 */
#define USB_XHCI_PHY_RESET_MASK2_PORTA	BIT(0)
#define USB_XHCI_PHY_RESET_MASK2_PORTB	BIT(3)

int usb_init(struct ast_chip *chip);

#endif
