/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ASPEED_PLATFORM_H_
#define _ASPEED_PLATFORM_H_

#if defined(CONFIG_SOC_AST2700_BOOTMCU) || defined(CONFIG_SOC_AST2705_BOOTMCU)
#include <platform_ast2700.h>
#elif defined(CONFIG_SOC_AST1040_BOOTMCU)
#include <platform_ast1040.h>
#else
#error "Unrecognized Aspeed platform."
#endif

#define DEBUG
#define AST_PLL_25MHZ			25000000
#define AST_PLL_24MHZ			24000000
#define AST_PLL_12MHZ			12000000

#endif /* _ASPEED_PLATFORM_H_ */
