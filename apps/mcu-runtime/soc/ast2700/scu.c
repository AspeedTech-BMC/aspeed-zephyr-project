/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <platform.h>
#include <zephyr/kernel.h>
#include <scu_ast2700.h>

int scu_init(struct ast_chip *chip)
{
	uint32_t reg;

	/* Restrict SCU1_010[5] (Enable secure boot) to bootmcu access only */
	reg = sys_read32(SCU1_HWSTRAP1_SEC1);
	sys_write32(reg | SCU1_HWSTRAP1_EN_SECBOOT, SCU1_HWSTRAP1_SEC1);

	reg = sys_read32(SCU1_HWSTRAP1_SEC2);
	sys_write32(reg | SCU1_HWSTRAP1_EN_SECBOOT, SCU1_HWSTRAP1_SEC2);

	reg = sys_read32(SCU1_HWSTRAP1_SEC3);
	sys_write32(reg | SCU1_HWSTRAP1_EN_SECBOOT, SCU1_HWSTRAP1_SEC3);

	return 0;
}
