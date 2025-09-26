/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _USB_H
#define _USB_H

#include <chip.h>

#define ASPEED_VHUBA1_BASE              0x12011000
#define  ASPEED_VHUBA1_PHY_CTL_1        (ASPEED_VHUBA1_BASE + 0x800)
#define  ASPEED_VHUBA1_PHY_CTL_2        (ASPEED_VHUBA1_BASE + 0x804)
#define  ASPEED_VHUBA1_PHY_CTL_3        (ASPEED_VHUBA1_BASE + 0x808)

#define ASPEED_VHUBB1_BASE              0x12021000
#define  ASPEED_VHUBB1_PHY_CTL_1        (ASPEED_VHUBB1_BASE + 0x800)
#define  ASPEED_VHUBB1_PHY_CTL_2        (ASPEED_VHUBB1_BASE + 0x804)
#define  ASPEED_VHUBB1_PHY_CTL_3        (ASPEED_VHUBB1_BASE + 0x808)

#define AST_VHUBC_BASE			(0x14120000)
#define AST_USB_UART_CTRL0		0x800
#define  AST_USB_COM_MODE_SEL		0x10
#define  AST_USB_COM_EN_CTRL		0x1C

#define AST_UDC_MAX_NUM_UART_PORTS	15


int usb_init(struct ast_chip *chip);

#endif
