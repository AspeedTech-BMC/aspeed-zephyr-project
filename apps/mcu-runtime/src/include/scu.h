/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ASM_ARCH_ASPEED_SCU_H
#define _ASM_ARCH_ASPEED_SCU_H

#if defined(CONFIG_SOC_AST1040_BOOTMCU)
#include <scu_ast1040.h>
#elif defined(CONFIG_SOC_AST2700_BOOTMCU) || defined(CONFIG_SOC_AST2705_BOOTMCU)
#include <scu_ast2700.h>
#else
#error "Unsupported SoC"	
#endif

#endif
