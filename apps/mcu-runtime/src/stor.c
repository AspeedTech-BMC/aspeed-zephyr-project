// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
 */

/* Notice, SPI driver operation should be moved to
 * driver layer after SPI driver is finished.
 * After that, normal Zephyr SPI driver should
 * be used.
 */

#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/logging/log.h>
#include <soc_fmc.h>
#include <stor.h>
#include <scu_ast2700.h>

LOG_MODULE_REGISTER(aspeed_stor, CONFIG_SOC_FMC_LOG_LEVEL);

enum boot_mode_type boot_mode(void)
{
	uint32_t dis, strap;

	dis = sys_read32(SCU1_OTPCFG_03_02);
	strap = sys_read32(SCU1_HWSTRAP1);

	/* check if recovery is disabled by OTP */
	if (!(dis & OTPCFG2_DIS_RECOVERY_MODE)) {
		/* check if recovery is enabled by hwstrap */
		if (strap & SCU1_HWSTRAP1_EN_RECOVERY_BOOT) {
			if ((strap & SCU1_HWSTRAP1_RECOVERY_INTERFACE) == SCU1_HWSTRAP1_RECOVERY_USB)
				return BOOT_DEV_USB;
			else if ((strap & SCU1_HWSTRAP1_RECOVERY_INTERFACE) == SCU1_HWSTRAP1_RECOVERY_I2C)
				return BOOT_DEV_I2C;
			else if ((strap & SCU1_HWSTRAP1_RECOVERY_INTERFACE) == SCU1_HWSTRAP1_RECOVERY_I3C)
				return BOOT_DEV_I3C;
			else
				return BOOT_DEV_UART;
		}
	}

	/* if not recovery mode, then it is storage */
	if ((strap & SCU1_HWSTRAP1_BOOT_EMMC_UFS)) {
		if (strap & SCU1_HWSTRAP1_BOOT_UFS)
			return BOOT_DEV_UFS;
		else
			return BOOT_DEV_MMC;
	}

	/* leave FWSPI as default for safety */
	return BOOT_DEV_SPI;
}
