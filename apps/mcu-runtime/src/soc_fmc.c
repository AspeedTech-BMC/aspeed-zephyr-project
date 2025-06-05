// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) ASPEED Technology Inc.
 */
#include <zephyr/sd/mmc.h>
#include <soc_fmc.h>
#include <stor.h>
#include <mmc.h>
#include <ufs.h>
#include <spi.h>

LOG_MODULE_REGISTER(soc_fmc, CONFIG_SOC_FMC_LOG_LEVEL);

int fit_load_image(enum boot_mode_type boot_mode, struct fit_image_info *fit_image)
{
	struct fit_load_info load;
	void *header = NULL;
	uint32_t blk = 0;
	int ret = -1;

	switch (boot_mode) {
	case BOOT_DEV_SPI:
		printf("Trying to boot from RAM\n");
		load.bl_len = 1;
		load.read = fit_ram_load_read;
		header = (void *)CONFIG_SOC_FMC_LOAD_FIT_ADDRESS;
		break;
	case BOOT_DEV_MMC:
		printf("Trying to boot from MMC\n");
		load.bl_len = 0x200;
		load.read = fit_mmc_load_read;

		blk = (CONFIG_SOC_FMC_LOAD_FIT_ADDRESS & 0xfffffff) / load.bl_len;
		header = (void *)CONFIG_SYS_LOAD_ADDR;

		/* Read fit header first */
		ret = fit_mmc_load_read(&load, blk, 1, header);

		break;
	case BOOT_DEV_UFS:
		printf("Trying to boot from UFS\n");
		load.bl_len = 0x1000;
		load.read = fit_scsi_load_read;
		blk = (CONFIG_SOC_FMC_LOAD_FIT_ADDRESS & 0xfffffff) / load.bl_len;
		header = (void *)CONFIG_SYS_LOAD_ADDR;

		/* Read fit header first */
		ret = fit_scsi_load_read(&load, blk, 1, header);

		break;
	case BOOT_DEV_UART:
		printf("Trying to boot from UART\n");
		break;
	case BOOT_DEV_USB:
		printf("Trying to boot from USB\n");
		break;
	case BOOT_DEV_I2C:
		printf("Trying to boot from I2C\n");
		break;
	case BOOT_DEV_I3C:
		printf("Trying to boot from I3C\n");
		break;
	default:
		printf("Unsupported booting device!");
		return ret;
	};

	if (image_get_magic(header) == FDT_MAGIC) {
		LOG_DBG("Found FIT");
		ret = fit_load_simple_fit(fit_image, &load, blk, header);
	} else {
		LOG_DBG("Wrong FDT Magic!!!");
		ret = -1;
	}

	return ret;
}
