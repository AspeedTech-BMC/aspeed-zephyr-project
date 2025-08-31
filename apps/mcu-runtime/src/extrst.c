// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Aspeed Technology Inc.
 */

#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <zephyr/kernel.h>
#include <extrst.h>

int extrst_mask_init(struct ast_chip *chip)
{
        uint32_t reg;

        /* only init EXTRST mask during power on reset */
        reg = sys_read32(SCU0_RESET_LOG1);
        if (!(reg & BIT(0)))
                return 0;

	sys_write32(SCU0_EXTRST_MASK_1_VAL, (SCU0_REG + 0x2F0));
	sys_write32(SCU0_EXTRST_MASK_2_VAL, (SCU0_REG + 0x2F4));

	sys_write32(SCU1_EXTRST_MASK_1_VAL, (SCU1_REG + 0x2F0));
	sys_write32(SCU1_EXTRST_MASK_2_VAL, (SCU1_REG + 0x2F4));
	sys_write32(SCU1_EXTRST_MASK_3_VAL, (SCU1_REG + 0x2F8));

	if (sys_read32(SCU1_HW_STRAP1) & BIT(3)) {
		reg = sys_read32((SCU1_REG + 0x2F4)) | BIT(1);
		sys_write32(reg, (SCU1_REG + 0x2F4));
	}

        return 0;
}
