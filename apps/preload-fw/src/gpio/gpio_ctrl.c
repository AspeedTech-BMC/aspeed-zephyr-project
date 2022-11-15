/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <logging/log.h>
#include "gpio_ctrl.h"
#include "sw_mailbox/sw_mailbox.h"

LOG_MODULE_REGISTER(gpio_ctrl);

static bool first_time_boot = true;

int BMCBootHold(void)
{
	const struct device *dev_m = NULL;

	/* Hold BMC Reset */
	pfr_bmc_extrst_enable_ctrl(true);
	// Only pull-up/down SRST in first bootup. Pull-up/down this pin in runtime will affect host
	// VGA function.
	if (first_time_boot)
		pfr_bmc_srst_enable_ctrl(true);
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

	if (first_time_boot) {
		pfr_bmc_srst_enable_ctrl(false);
		first_time_boot = false;
	}

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

void BMCSPIHold(uint8_t ext_mux_level)
{
	const struct device *dev_m = NULL;
	enum spim_ext_mux_sel mux_sel;

	mux_sel = (ext_mux_level) ? SPIM_EXT_MUX_SEL_0 : SPIM_EXT_MUX_SEL_1;
	LOG_INF("Hold BMC SPI");
	dev_m = device_get_binding(BMC_SPI_MONITOR);
	spim_ext_mux_config(dev_m, mux_sel);

#if defined(CONFIG_BMC_DUAL_FLASH)
	dev_m = device_get_binding(BMC_SPI_MONITOR_2);
	spim_ext_mux_config(dev_m, mux_sel);
#endif
}

void BMCSPIRelease(uint8_t ext_mux_level)
{
	const struct device *dev_m = NULL;
	enum spim_ext_mux_sel mux_sel;

	mux_sel = (ext_mux_level) ? SPIM_EXT_MUX_SEL_1 : SPIM_EXT_MUX_SEL_0;

	dev_m = device_get_binding(BMC_SPI_MONITOR);
	spim_ext_mux_config(dev_m, mux_sel);
#if defined(CONFIG_BMC_DUAL_FLASH)
	dev_m = device_get_binding(BMC_SPI_MONITOR_2);
	spim_ext_mux_config(dev_m, mux_sel);
#endif

	LOG_INF("release BMC SPI");
}

