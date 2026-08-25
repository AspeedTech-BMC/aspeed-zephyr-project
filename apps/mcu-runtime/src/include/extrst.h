/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ASPEED_EXTRST_H_
#define _ASPEED_EXTRST_H_

#include <chip.h>

#if defined(CONFIG_SOC_AST2700_BOOTMCU) || defined(CONFIG_SOC_AST2705_BOOTMCU)
#include <extrst_ast2700.h>
#elif defined(CONFIG_SOC_AST1040_BOOTMCU)
#include <extrst_ast1040.h>
#else
#error "Unrecognized Aspeed platform."
#endif

int extrst_mask_init(struct ast_chip *chip);

#endif
