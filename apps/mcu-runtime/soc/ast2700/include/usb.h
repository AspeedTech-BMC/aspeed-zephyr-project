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

/* Standard EHCI host controller register blocks (distinct from the BEHCI
 * vendor extension block above). Ports A/B/C/D each have their own EHCI.
 */
#define ASPEED_EHCI0_BASE              0x12061000	/* Port A */
#define ASPEED_EHCI1_BASE              0x12063000	/* Port B */
#define ASPEED_EHCI2_BASE              0x14121000	/* Port C */
#define ASPEED_EHCI3_BASE              0x14123000	/* Port D */

/* Standard xHCI host controller register blocks. Only ports A/B have
 * an xHCI/USB3 PHY.
 */
#define ASPEED_XHCI0_BASE              0x12030000	/* Port A */
#define ASPEED_XHCI1_BASE              0x12050000	/* Port B */

/* EHCI/xHCI operational registers start at CAPLENGTH bytes past the
 * controller base.
 */
#define  ASPEED_USB_HC_CAPLENGTH_MASK    GENMASK(7, 0)
#define  ASPEED_USB_HC_USBCMD            0x00
#define  ASPEED_USB_HC_USBSTS            0x04
#define  ASPEED_USB_HC_USBINTR           0x08

/* EHCI: Run/Stop can't be cleared directly -- the async/periodic
 * schedules must be disabled and given time to actually halt first.
 */
#define  ASPEED_USB_EHCI_CMD_PSE         BIT(4)
#define  ASPEED_USB_EHCI_CMD_ASE         BIT(5)
#define  ASPEED_USB_EHCI_CMD_RUN         BIT(0)
#define  ASPEED_USB_EHCI_STS_PSS         BIT(14)
#define  ASPEED_USB_EHCI_STS_ASS         BIT(15)
#define  ASPEED_USB_EHCI_STS_HALT        BIT(12)

/* xHCI: Run/Stop can be cleared directly. */
#define  ASPEED_USB_XHCI_CMD_RUN         BIT(0)
#define  ASPEED_USB_XHCI_STS_HALT        BIT(0)

/*
 * xHCI1 are dual-role: GCTL.PRTCAPDIR says whether a port is currently
 * acting as a host (in which case the USBCMD/USBSTS pair above applies)
 * or as a UDC gadget (DRD port B can run as a device) -- in the latter
 * case the host-mode Run/Stop bit means nothing, and DCTL/DSTS is the
 * pair that actually needs to be quiesced instead. All three live in the
 * same global/device register block at a fixed offset from the
 * controller base, regardless of which mode it's in.
 */
#define  ASPEED_USB_XHCI_GCTL             0xc110
#define  ASPEED_USB_XHCI_GCTL_PRTCAPDIR_MASK  GENMASK(13, 12)
#define  ASPEED_USB_XHCI_GCTL_PRTCAP_HOST     1
#define  ASPEED_USB_XHCI_GCTL_PRTCAP_DEVICE   2
#define  ASPEED_USB_XHCI_GCTL_PRTCAP_OTG      3

#define  ASPEED_USB_XHCI_DCTL             0xc704
#define  ASPEED_USB_XHCI_DCTL_RUN_STOP        BIT(31)

#define  ASPEED_USB_XHCI_DSTS             0xc70c
#define  ASPEED_USB_XHCI_DSTS_DEVCTRLHLT      BIT(22)

/*
 * usb_func_ctrl (SCU410) port1/port2 XHCI mode select: 0 = PCIe XHCI,
 * 1 = BMC XHCI. A PCIe-XHCI port's DMA is the PCIe host's problem, not
 * ours -- it doesn't go through this SoC's WDT reset domain.
 */
#define  ASPEED_USB_FUNC_XHCI_PORTA_BMC  BIT(9)
#define  ASPEED_USB_FUNC_XHCI_PORTB_BMC  BIT(10)

/*
 * usb_func_ctrl (SCU410) port1/port2 EHCI mode select (2-bit field):
 *   00: PCIe EHCI to vHub   10: BMC EHCI to PHY
 *   01: vHub to PHY         11: PCIe EHCI to PHY
 * Only "BMC EHCI to PHY" is a locally-owned EHCI whose DMA we need to
 * stop -- the other three either belong to the PCIe host or never run
 * the EHCI controller (vHub-to-PHY device mode) at all.
 */
#define  ASPEED_USB_FUNC_PORTA_MODE_SHIFT      24
#define  ASPEED_USB_FUNC_PORTB_MODE_SHIFT      28
#define  ASPEED_USB_FUNC_PORT_MODE_MASK        0x3
#define  ASPEED_USB_FUNC_MODE_BMC_EHCI_TO_PHY  2

/*
 * usb_func_ctrl (SCU410) port1/port2 XHCI "U2" mode select (2-bit
 * field, same shift as usb.c's u2_xhci_shift): 00 = XHCI to vHub1,
 * 01 = vHub1 to PHY, 10 = XHCI to PHY, 11 = XHCI Ext (unsupported).
 *
 * This field and the EHCI mode field above share one encoding: bit 1
 * of the 2-bit value is the "does the host controller bypass vHub
 * straight to the PHY" flag. 0 (00/01) means vHub0 (EHCI mode) or
 * vHub1 (this field) is actually on the data path; 1 (10/11) means
 * it's bypassed and idle, regardless of who owns the host controller.
 */
#define  ASPEED_USB_FUNC_PORTA_U2_SHIFT        2
#define  ASPEED_USB_FUNC_PORTB_U2_SHIFT        6
#define  ASPEED_USB_FUNC_MODE_VHUB_BYPASS      BIT(1)

/*
 * usb_ctrl (SCU1 0x3b0) port C/D function select. Unlike ports A/B,
 * each port here is a plain selector between vHub and EHCI (Port C
 * also has a USB2UART option) -- not a shared "bypass" encoding.
 */
#define  ASPEED_USB_CTRL_USBC_SEL_SHIFT   0
#define  ASPEED_USB_CTRL_USBD_SEL_SHIFT   2
#define  ASPEED_USB_CTRL_SEL_MASK         0x3
#define  ASPEED_USB_CTRL_USBC_SEL_UART_VHUB  0	/* USBUart + vHub */
#define  ASPEED_USB_CTRL_USBC_SEL_VHUB       1
#define  ASPEED_USB_CTRL_USBC_SEL_EHCI        2
#define  ASPEED_USB_CTRL_USBC_SEL_UART        3
#define  ASPEED_USB_CTRL_USBD_SEL_VHUB        1
#define  ASPEED_USB_CTRL_USBD_SEL_EHCI        2

/* UHCI companion controllers (USB1.1): uhci0 serves ports A/B, uhci1
 * serves ports C/D. Aspeed maps every (16-bit) UHCI register onto its
 * own 32-bit-aligned MMIO slot.
 */
#define ASPEED_UHCI0_BASE              0x12040000	/* Ports A/B */
#define ASPEED_UHCI1_BASE              0x14110000	/* Ports C/D */
#define  ASPEED_USB_UHCI_USBCMD          0x00
#define  ASPEED_USB_UHCI_USBCMD_RS       BIT(0)
#define  ASPEED_USB_UHCI_USBSTS          0x04
#define  ASPEED_USB_UHCI_STS_HCH         BIT(5)	/* HC Halted */

/* vHub (device-mode) controllers. Ports A/B each have two: vhub0 pairs
 * with EHCI, vhub1 pairs with the xHCI/USB3 PHY. Ports C/D only have
 * the EHCI-side vhub.
 */
#define ASPEED_VHUBA0_BASE              0x12060000
#define ASPEED_VHUBB0_BASE              0x12062000
#define ASPEED_VHUBA1_BASE              0x12011000
#define ASPEED_VHUBB1_BASE              0x12021000
#define ASPEED_VHUBD_BASE               0x14122000	/* Port C is AST_VHUBC_BASE above */

#define  ASPEED_USB_VHUB_CTRL              0x00
#define  ASPEED_USB_VHUB_CTRL_UPSTREAM_CONNECT   BIT(0)

/* Per-downstream-device block: base + 0x100 + 0x10 * device index */
#define  ASPEED_USB_VHUB_DEV_BLOCK_BASE     0x100
#define  ASPEED_USB_VHUB_DEV_BLOCK_STRIDE   0x10
#define  ASPEED_USB_VHUB_NUM_DEVS           7
#define  ASPEED_USB_VHUB_DEV_EN_CTRL        0x00
#define  ASPEED_USB_VHUB_DEV_EN_ENABLE_PORT      BIT(0)

/* Per-generic-endpoint block: base + 0x200 + 0x10 * endpoint index */
#define  ASPEED_USB_VHUB_EP_BLOCK_BASE      0x200
#define  ASPEED_USB_VHUB_EP_BLOCK_STRIDE    0x10
#define  ASPEED_USB_VHUB_NUM_GEN_EPS        21
#define  ASPEED_USB_VHUB_EP_CONFIG          0x00
#define  ASPEED_USB_VHUB_EP_CFG_ENABLE            BIT(0)

int usb_init(struct ast_chip *chip);
int usb_ehci_stop(struct ast_chip *chip);
int usb_uhci_stop(struct ast_chip *chip);
int usb_xhci_stop(struct ast_chip *chip);
int usb_vhub_stop(struct ast_chip *chip);
#endif
