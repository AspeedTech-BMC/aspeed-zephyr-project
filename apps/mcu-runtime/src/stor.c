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
#include <ast_loader.h>
#include <chip.h>

LOG_MODULE_REGISTER(ast_stor, CONFIG_SOC_FMC_LOG_LEVEL);

struct image_info {
	int id;
	uint32_t offset;
	uint32_t size;
};

static struct image_info img_info[] = {
	{0, 0, 0},
	{CPTRA_FMC_FW_ID, 0, 0},
	{CPTRA_DDR4_IMEM_FW_ID, 0, 0},
	{CPTRA_DDR4_DMEM_FW_ID, 0, 0},
	{CPTRA_DDR4_2D_IMEM_FW_ID, 0, 0},
	{CPTRA_DDR4_2D_DMEM_FW_ID, 0, 0},
	{CPTRA_DDR5_IMEM_FW_ID, 0, 0},
	{CPTRA_DDR5_DMEM_FW_ID, 0, 0},
	{CPTRA_DP_FW_FW_ID, 0, 0},
	{CPTRA_UEFI_FW_ID, 0, 0},
};

static int stor_get_image_info(struct image_info *info)
{
	uint32_t manifest_base = CPTRA_MANIFEST_OFFSET;
	uint32_t offset, sz;
	int err;

	if (!info) {
		LOG_ERR("Image info pointer is NULL.\n");
		return -1;
	}

	for (int i = 2; i < CPTRA_UEFI_FW_ID + 1; i++) {
		/* Call cptra's service to get the image info */
		err = cptra_hdr_get_prebuilt(info[i].id, &offset, &sz);
		if (err) {
			LOG_ERR("Failed to get image info for ID %d, err=%d\n", info[i].id, err);
			return err;
		}

		info[i].offset = offset + manifest_base;
		info[i].size = sz;
	}

	return err;
}

static int stor_load(struct ast_loader *loader, uint32_t type, uint32_t *dst, uint32_t *len)
{
        struct ast_loader_ops *ops;
        uint32_t src, sz = 0;
        int err = 0;

        src = img_info[type].offset;
	sz = img_info[type].size;

        ops = ast_loader_get_ops(loader);
        if (ops && ops->copy)
                err = ops->copy(loader->dev, dst, src, sz);

        *len = sz;

        return err;
}

int stor_init(struct ast_loader *loader)
{
        struct ast_loader_ops *ops;
        int bootmode;
        int err = -1;

        bootmode = loader->bootmode;

        if (bootmode == BOOT_DEVICE_RAM)
		err = spi_register(loader);
        else if (bootmode == BOOT_DEVICE_MMC1)
		err = mmc_register(loader);
        else if (bootmode == BOOT_DEVICE_SATA)
		err = ufs_register(loader);
        else
                return -1;

        if (err) {
                printf("Get stor udevice Failed %d.\n", err);
                return err;
        }

        loader->load = stor_load;

        ops = ast_loader_get_ops(loader);
        if (ops && ops->init)
                err = ops->init(loader->dev);

	stor_get_image_info(img_info);

        return err;
}
