/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/drivers/spi_nor.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/drivers/gpio.h>
#include "gpio_aspeed.h"
#include "platform/platform_gpio_ctrl.h"

#define LOG_MODULE_NAME gpio_api

#if !DT_NODE_HAS_STATUS(DT_INST(0, aspeed_pfr_gpio_common), okay)
#error "no correct pfr gpio device"
#endif

LOG_MODULE_REGISTER(LOG_MODULE_NAME);
static bool first_time_boot = true;

static void bmc_srst_enable_ctrl(bool enable)
{
	int ret;
	const struct gpio_dt_spec srst_gpio =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common),
						bmc_srst_ctrl_out_gpios, 0);

	if (enable)
		gpio_pin_set(srst_gpio.port, srst_gpio.pin, 0);
	else
		gpio_pin_set(srst_gpio.port, srst_gpio.pin, 1);

	ret = gpio_pin_configure_dt(&srst_gpio, GPIO_OUTPUT);
	if (ret)
		return;

	k_busy_wait(10000); /* 10ms */
}

static void bmc_extrst_enable_ctrl(bool enable)
{
	int ret;
	const struct gpio_dt_spec extrst_gpio =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common),
						bmc_extrst_ctrl_out_gpios, 0);

	if (enable)
		gpio_pin_set(extrst_gpio.port, extrst_gpio.pin, 0);
	else
		gpio_pin_set(extrst_gpio.port, extrst_gpio.pin, 1);

	ret = gpio_pin_configure_dt(&extrst_gpio, GPIO_OUTPUT);
	if (ret)
		return;

	k_busy_wait(10000); /* 10ms */
}

int BMCBootHold(void)
{
	const struct device *dev_m = NULL;
	const struct device *flash_dev = NULL;

	/* Hold BMC Reset */
	bmc_extrst_enable_ctrl(true);
	// Only pull-up/down SRST in first bootup. Pull-up/down this pin in runtime will affect host
	// VGA function.
	if (first_time_boot)
		bmc_srst_enable_ctrl(true);
	dev_m = device_get_binding(BMC_SPI_MONITOR);
	/* config spi monitor as master mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);
	flash_dev = device_get_binding("spi1@0");
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind spi1@0");
	}
#if defined(CONFIG_BMC_DUAL_FLASH)
	dev_m = device_get_binding(BMC_SPI_MONITOR_2);
	/* config spi monitor as master mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);
	flash_dev = device_get_binding("spi1@1");
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind spi1@1");
	}
#endif
	LOG_INF("hold BMC");
	return 0;
}

int PCHBootHold(void)
{
	const struct device *dev_m = NULL;
	const struct device *flash_dev = NULL;
	const struct platform_gpio_ctrl_ops *gpio_ops = get_platform_gpio_ctrl_ops();

	if (gpio_ops->pch_hold) {
		gpio_ops->pch_hold();
	} else {
		LOG_ERR("Failed to hold PCH");
		return -1;
	}

	dev_m = device_get_binding(PCH_SPI_MONITOR);
	/* config spi monitor as master mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);
	flash_dev = device_get_binding("spi2@0");
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind spi2@0");
	}

#if defined(CONFIG_CPU_DUAL_FLASH)
	dev_m = device_get_binding(PCH_SPI_MONITOR_2);
	/* config spi monitor as master mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);
	flash_dev = device_get_binding("spi2@1");
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind spi2@1");
	}
#endif
	LOG_INF("hold PCH");
	return 0;
}

int BMCBootRelease(void)
{
	const struct device *dev_m = NULL;
	const struct device *flash_dev = NULL;

	flash_dev = device_get_binding("spi1@0");
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind spi1@0");
	}
	dev_m = device_get_binding(BMC_SPI_MONITOR);
	aspeed_spi_monitor_sw_rst(dev_m);
	/* config spi monitor as monitor mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
#if defined(CONFIG_BMC_DUAL_FLASH)
	flash_dev = device_get_binding("spi1@1");
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind spi1@1");
	}
	dev_m = device_get_binding(BMC_SPI_MONITOR_2);
	aspeed_spi_monitor_sw_rst(dev_m);
	/* config spi monitor as monitor mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
#endif
	if (first_time_boot) {
		bmc_srst_enable_ctrl(false);
		first_time_boot = false;
	}

	bmc_extrst_enable_ctrl(false);
	LOG_INF("release BMC");
	return 0;
}

int PCHBootRelease(void)
{
	const struct device *dev_m = NULL;
	const struct device *flash_dev = NULL;
	const struct platform_gpio_ctrl_ops *gpio_ops = get_platform_gpio_ctrl_ops();

	flash_dev = device_get_binding("spi2@0");
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind spi2@0");
	}
	dev_m = device_get_binding(PCH_SPI_MONITOR);
	aspeed_spi_monitor_sw_rst(dev_m);
	/* config spi monitor as monitor mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);

#if defined(CONFIG_CPU_DUAL_FLASH)
	flash_dev = device_get_binding("spi2@1");
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind spi2@1");
	}
	dev_m = device_get_binding(PCH_SPI_MONITOR_2);
	aspeed_spi_monitor_sw_rst(dev_m);
	/* config spi monitor as monitor mode */
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
#endif

	if (gpio_ops->pch_release) {
		gpio_ops->pch_release();
		LOG_INF("release PCH");
	} else {
		LOG_ERR("Failed to release PCH");
		return -1;
	}
	return 0;
}

void RTCRSTControl(bool assert)
{
	const struct platform_gpio_ctrl_ops *gpio_ops = get_platform_gpio_ctrl_ops();
	if (gpio_ops->rst_rtcrst) {
		gpio_ops->rst_rtcrst(assert);
	} else {
		LOG_WRN("RTC Reset callback is not registered");
		return;
	}
}

void RSTPlatformReset(bool assert)
{
	const struct platform_gpio_ctrl_ops *gpio_ops = get_platform_gpio_ctrl_ops();
	if (gpio_ops->rst_pltrst) {
		gpio_ops->rst_pltrst(assert);
	} else {
		LOG_WRN("RST Platform Reset callback is not registered");
		return;
	}
}

#if defined(CONFIG_PFR_MCTP_I3C)
int i3c_mng_mux_owner = I3C_MNG_OWNER_BMC;
void switch_i3c_mng_owner(int owner)
{
	const struct platform_gpio_ctrl_ops *gpio_ops = get_platform_gpio_ctrl_ops();
	if (gpio_ops->i3c_mng_switch) {
		gpio_ops->i3c_mng_switch(owner);
	} else {
		LOG_WRN("I3C MNG switch callback is not registered");
		return;
	}
}

int get_i3c_mng_owner(void)
{
	return i3c_mng_mux_owner;
}
#endif

