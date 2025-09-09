/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/logging/log.h>
#include <ast_loader.h>
#include <chip.h>

LOG_MODULE_REGISTER(ast_recovery, CONFIG_SOC_FMC_LOG_LEVEL);

struct message_info {
	int id;
	char *msg;
};

static struct message_info message[] = {
	{0, NULL},
	{CPTRA_FMC_FW_ID,		   "\n"},
	{CPTRA_DDR4_IMEM_FW_ID,		"ddr4_pmu_train_imem.bin"},
	{CPTRA_DDR4_DMEM_FW_ID,		"ddr4_pmu_train_dmem.bin"},
	{CPTRA_DDR4_2D_IMEM_FW_ID,	"ddr4_2d_pmu_train_imem.bin"},
	{CPTRA_DDR4_2D_DMEM_FW_ID,	"ddr4_2d_pmu_train_dmem.bin"},
	{CPTRA_DDR5_IMEM_FW_ID,		"ddr5_pmu_train_imem.bin"},
	{CPTRA_DDR5_DMEM_FW_ID,		"ddr5_pmu_train_dmem.bin"},
	{CPTRA_DP_FW_FW_ID,		"dp_fw.bin"},
	{CPTRA_UEFI_FW_ID,		"uefi_ast2700.bin"},
	{CPTRA_ATF_FW_ID,		"atf.bin"},
	{CPTRA_OPTEE_FW_ID,		"optee.bin"},
	{CPTRA_UBOOT_FW_ID,		"u-boot.bin"},
	{CPTRA_SSP_FW_ID,		"ast2700-ssp.bin"},
	{CPTRA_TSP_FW_ID,		"ast2700-tsp.bin"},
};

static int recovery_load(struct ast_loader *loader, uint32_t type, uint32_t *dst, uint32_t *len)
{
	struct ast_loader_ops *ops;
	uint32_t sz;
	int err = -1;

	printf("Please send \"%s\" through recovery interface.\n", message[type].msg);

	ops = ast_loader_get_ops(loader);
	if (ops && ops->load)
		err = ops->load(loader->dev, dst, &sz);

	*len = sz;

	return err;
}

int recovery_init(struct ast_loader *loader)
{
	struct ast_loader_ops *ops;
	int bootmode;
	int err = -1;

	bootmode = loader->bootmode;

	if (bootmode == BOOT_DEVICE_USB)
		err = usb_register(loader);
	else if (bootmode == BOOT_DEVICE_I2C)
		err = i2c_register(loader);
	else if (bootmode == BOOT_DEVICE_I3C)
		err = i3c_register(loader);
	else if (bootmode == BOOT_DEVICE_UART)
		err = uart_register(loader);
	else
		return -1;

	if (err) {
		LOG_ERR("Get recovery udevice Failed %d.\n", err);
		return err;
	}

	loader->load = recovery_load;

	ops = ast_loader_get_ops(loader);
	if (ops && ops->init)
		err = ops->init(loader->dev);

	return err;
}
