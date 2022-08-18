/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <drivers/flash.h>
#include <drivers/spi_nor.h>
#include <gpio/gpio_aspeed.h>
#include <kernel.h>
#include <sys/util.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr.h>
#include <drivers/gpio.h>
#include <drivers/misc/aspeed/pfr_aspeed.h>

#define LOG_MODULE_NAME gpio_api

LOG_MODULE_REGISTER(LOG_MODULE_NAME);
static bool first_time_boot = true;

int BMCBootHold(void)
{
	const struct device *dev_m = NULL;

	/* Hold BMC Reset */
	pfr_bmc_extrst_enable_ctrl(true);
#if !defined(CONFIG_ASPEED_DC_SCM)
	// Only pull-up/down SRST in first bootup. Pull-up/down this pin in runtime will affect host
	// VGA function.
	if (first_time_boot)
		pfr_bmc_srst_enable_ctrl(true);
#endif
	dev_m = device_get_binding(BMC_SPI_MONITOR);
	spim_rst_flash(dev_m, 10);
	spim_passthrough_config(dev_m, 0, false);
	/* config spi monitor as master mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);
#if defined(CONFIG_BMC_DUAL_FLASH)
	dev_m = device_get_binding(BMC_SPI_MONITOR_2);
	spim_rst_flash(dev_m, 10);
	spim_passthrough_config(dev_m, 0, false);
	/* config spi monitor as master mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);
#endif

	return 0;
}

int PCHBootHold(void)
{
	const struct device *dev_m = NULL;

	/* Hold PCH Reset */
	pfr_pch_rst_enable_ctrl(true);

	dev_m = device_get_binding(PCH_SPI_MONITOR);
	spim_rst_flash(dev_m, 10);
	spim_passthrough_config(dev_m, 0, false);
	/* config spi monitor as master mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);

	return 0;
}

int BMCBootRelease(void)
{
	const struct device *dev_m = NULL;

	dev_m = device_get_binding(BMC_SPI_MONITOR);
	spim_rst_flash(dev_m, 10);
	spim_passthrough_config(dev_m, 0, false);
	aspeed_spi_monitor_sw_rst(dev_m);
	/* config spi monitor as monitor mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
#if defined(CONFIG_BMC_DUAL_FLASH)
	dev_m = device_get_binding(BMC_SPI_MONITOR_2);
	spim_rst_flash(dev_m, 10);
	spim_passthrough_config(dev_m, 0, false);
	aspeed_spi_monitor_sw_rst(dev_m);
	/* config spi monitor as monitor mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
#endif

#if !defined(CONFIG_ASPEED_DC_SCM)
	if (first_time_boot) {
		pfr_bmc_srst_enable_ctrl(false);
		first_time_boot = false;
	}
#endif

	pfr_bmc_extrst_enable_ctrl(false);
	LOG_INF("release BMC");
	return 0;
}

int PCHBootRelease(void)
{
	const struct device *dev_m = NULL;

	dev_m = device_get_binding(PCH_SPI_MONITOR);
	spim_rst_flash(dev_m, 10);
	spim_passthrough_config(dev_m, 0, false);
	aspeed_spi_monitor_sw_rst(dev_m);
	/* config spi monitor as monitor mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);

	pfr_pch_rst_enable_ctrl(false);
	LOG_INF("release PCH");
	return 0;
}

