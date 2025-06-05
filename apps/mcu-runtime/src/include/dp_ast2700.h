/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Aspeed Technology Inc.
 */
#ifndef _ASM_ARCH_DP_AST2700_H
#define _ASM_ARCH_DP_AST2700_H

#define MCU_BASE			(0x11000000)
#define MCU_DMEM_BASE			(MCU_BASE)
#define MCU_REG_BASE			(MCU_BASE + 0x10000)
#define MCU_IMEM_BASE			(MCU_BASE + 0x20000)

#define MCU_CTRL			(MCU_REG_BASE + 0x00e0)
#define  MCU_CTRL_AHBS_IMEM_EN		BIT(0)
#define  MCU_CTRL_AHBS_SW_RST		BIT(4)
#define  MCU_CTRL_AHBM_SW_RST		BIT(8)
#define  MCU_CTRL_CORE_SW_RST		BIT(12)
#define  MCU_CTRL_DMEM_SHUT_DOWN	BIT(16)
#define  MCU_CTRL_DMEM_SLEEP		BIT(17)
#define  MCU_CTRL_DMEM_CLK_OFF		BIT(18)
#define  MCU_CTRL_IMEM_SHUT_DOWN	BIT(20)
#define  MCU_CTRL_IMEM_SLEEP		BIT(21)
#define  MCU_CTRL_IMEM_CLK_OFF		BIT(22)
#define  MCU_CTRL_IMEM_SEL		BIT(24)
#define  MCU_CTRL_CONFIG		BIT(28)

#define MCU_INTR_CTRL			(MCU_REG_BASE + 0x00e8)
#define  MCU_INTR_CTRL_CLR		GENMASK(7, 0)
#define  MCU_INTR_CTRL_MASK		GENMASK(15, 8)
#define  MCU_INTR_CTRL_EN		GENMASK(23, 16)

#define DP_BASE				(0x12c0a000)
#define DP_VERSION			(DP_BASE + 0x01C)
#define DP_HANDSHAKE			(DP_BASE + 0x0B8)
#define  DP_HANDSHAKE_HOST_READ_EDID	BIT(28)
#define  DP_HANDSHAKE_VIDEO_FMT_SRC	BIT(24)

int dp_init(void);

#endif
