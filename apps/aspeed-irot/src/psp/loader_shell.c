/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>

#include <psp/loader.h>

#if defined(CONFIG_SHELL)
#include <zephyr/shell/shell.h>

static int init_deferred_device(const struct shell *shell, const char *name)
{
	const struct device *devlist;
	size_t devcnt = z_device_get_all_static(&devlist);
	const struct device *devlist_end = devlist + devcnt;
	const struct device *fmc_dev;

	int ret = 0;

	for (fmc_dev = devlist; fmc_dev < devlist_end; fmc_dev++) {
		if (strcmp(fmc_dev->name, name) == 0) {
			break;
		}
	}

	if( !fmc_dev) {
		shell_print(shell, "Failed to get FMC device binding %s.", name);
		return 0;
	}

	if (device_is_ready(fmc_dev)) {
		shell_print(shell, "Device %s is ready.", name);
	} else {
		ret = device_init(fmc_dev);
		shell_print(shell, "device %s init returned %d", name, ret);
	}

	return ret;

}

int cmd_psp_init(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Initializing SPI...");

	/* Add code to initialize the SPI interface here */
	/* For example, configure SPI pins, set up SPI parameters, etc. */

	init_deferred_device(shell, "spi@74000000");
	init_deferred_device(shell, "fmc@0");

	// Fionding the device structure
	shell_print(shell, "SPI initialized successfully.");
	return 0;
}

int cmd_psp_load(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Releasing PSP...");

	/* Add code to release the Primary Processor here */
	aspeed_load_image(argv[1]);

	shell_print(shell, "PSP released successfully.");
	return 0;
}

int cmd_psp_boot(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Booting CPU...");

	/* Add code to boot the CPU here */
	aspeed_prepare_for_boot();

	shell_print(shell, "CPU booted successfully.");
	return 0;
}

int cmd_psp_run(const struct shell *shell, size_t argc, char **argv)
{
	shell_print(shell, "Running CPU...");

	/* Add code to run the CPU here */
	aspeed_load_image("all");
	aspeed_prepare_for_boot();

	shell_print(shell, "CPU is now running.");
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_psp,
	SHELL_CMD(init, NULL, "Init SPI", cmd_psp_init),
	SHELL_CMD(load, NULL, "Load Image", cmd_psp_load),
	SHELL_CMD(boot, NULL, "Boot CPU", cmd_psp_boot),
	SHELL_CMD(run, NULL, "Run CPU", cmd_psp_run),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(psp, &sub_psp, "Primary Processor Control", NULL);
#endif
