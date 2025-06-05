/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ASPEED_PLATFORM_H_
#define _ASPEED_PLATFORM_H_

#define DEBUG
#define AST_PLL_25MHZ			25000000
#define AST_PLL_24MHZ			24000000
#define AST_PLL_12MHZ			12000000

/* DRAM base address from the hardware's perspective */
#define SYS_DRAM_BASE			0x400000000ULL

/*********************************************************************************/
#if defined(CONFIG_SOC_AST2700_BOOTMCU)
#define ASPEED_AHBC0_BASE		0x12000000
#define SCU0_REG			0x12c02000
#define SCU0_REVISION_ID		(SCU0_REG + 0x000)
#define SCU0_HW_STRAP1			(SCU0_REG + 0x010)
#define SCU0_HW_STRAP1_CLR		(SCU0_REG + 0x014)
#define SCU0_RESET_LOG1			(SCU0_REG + 0x050)
#define SCU0_RESET_LOG2			(SCU0_REG + 0x060)
#define SCU0_RESET_LOG3			(SCU0_REG + 0x070)
#define SCU0_CA35_REL			(SCU0_REG + 0x10c)
#define SCU0_CA35_RVBAR0		(SCU0_REG + 0x110)
#define SCU0_CA35_RVBAR1		(SCU0_REG + 0x114)
#define SCU0_CA35_RVBAR2		(SCU0_REG + 0x118)
#define SCU0_CA35_RVBAR3		(SCU0_REG + 0x11c)
#define SCU0_CPU_SMP_EP0		(SCU0_REG + 0x780)
#define SCU0_CPU_SMP_EP1		(SCU0_REG + 0x788)
#define SCU0_CPU_SMP_EP2		(SCU0_REG + 0x790)
#define SCU0_CPU_SMP_EP3		(SCU0_REG + 0x798)
#define SLI0_REG			0x12c17000
#define ASPEED_MAC_COUNT		3
#define ASPEED_DRAM_BASE		0x80000000
#define ASPEED_SRAM_BASE		0x10000000
#define ASPEED_SRAM_SIZE		0x20000
#define ASPEED_FMC_REG_BASE		0x14000000
#define ASPEED_FMC_CS0_BASE		0x20000000
#define ASPEED_FMC_CS0_SIZE		0x10000000
#define ASPEED_AHBC1_BASE		0x140b0000
#define SCU1_REG			0x14c02000
#define SCU1_REVISION_ID		(SCU1_REG + 0x000)
#define SCU1_HW_STRAP1			(SCU1_REG + 0x010)
#define SCU1_RESET_LOG1			(SCU1_REG + 0x050)
#define SCU1_RESET_LOG2			(SCU1_REG + 0x060)
#define SCU1_RESET_LOG3			(SCU1_REG + 0x070)
#define SCU1_RESET_LOG4			(SCU1_REG + 0x080)
#define SCU1_MISC			(SCU1_REG + 0x0c0)
#define   SCU1_MISC_SIO_LTPI_EN		BIT(3)
#define ASPEED_IO_INTC_BASE		0x14C18000
#define SLI1_REG			0x14c1e000
#define LTPI0_BASE			0x14c34000
#define LTPI1_BASE			0x14c35000
#define ASPEED_WDT_BASE			0x14c37000
#define WDTA_REG			0x14c37400
#else
#error "Unrecognized Aspeed platform."
#endif

#endif
