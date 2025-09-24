/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ASPEED_EXTRST_H_
#define _ASPEED_EXTRST_H_

#include <chip.h>

#define SCU0_EXTRST_MASK_1_VAL  0x8207ff71
#define SCU0_EXTRST_MASK_2_VAL  0x000003f6

#define SCU1_EXTRST_MASK_1_VAL  0x000093ec
#define SCU1_EXTRST_MASK_2_VAL  0x40303801
#define SCU1_EXTRST_MASK_3_VAL  0x00320000

int extrst_mask_init(struct ast_chip *chip);

#endif
