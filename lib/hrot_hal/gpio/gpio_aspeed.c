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

int BMCBootHold(void)
{
	const struct device *dev_m = NULL;

	/* Hold BMC Reset */
	pfr_bmc_extrst_enable_ctrl(true);
#if !defined(CONFIG_ASPEED_DC_SCM)
	pfr_bmc_srst_enable_ctrl(true);
#endif
	dev_m = device_get_binding(BMC_SPI_MONITOR);
	spim_rst_flash(dev_m, 10);
	spim_passthrough_config(dev_m, 0, false);
	/* config spi monitor as master mode */
#if defined(CONFIG_ASPEED_DC_SCM)
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_SEL_1);
#else
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_SEL_0);
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
#if defined(CONFIG_ASPEED_DC_SCM)
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_SEL_1);
#else
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_SEL_0);
#endif
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
#if defined(CONFIG_ASPEED_DC_SCM)
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_SEL_0);
#else
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_SEL_1);
	pfr_bmc_srst_enable_ctrl(false);
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
#if defined(CONFIG_ASPEED_DC_SCM)
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_SEL_0);
#else
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_SEL_1);
#endif

	pfr_pch_rst_enable_ctrl(false);
	LOG_INF("release PCH");
	return 0;
}

