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
#include "flash/flash_aspeed.h"

#define LOG_MODULE_NAME gpio_api

#if !DT_NODE_HAS_STATUS(DT_INST(0, aspeed_pfr_gpio_common), okay)
#error "no correct pfr gpio device"
#endif

LOG_MODULE_REGISTER(LOG_MODULE_NAME);
static bool first_time_boot = true;

struct aspeed_spim_config {
	mm_reg_t ctrl_base;
	uint32_t irq_num;
	uint32_t irq_priority;
	uint32_t ctrl_idx;
	uint32_t ext_mux_sel_default;
	bool extra_clk_en;
	bool force_rel_flash_rst;
	const struct device *parent;
	const struct gpio_dt_spec *ext_mux_sel_gpios;
	uint32_t ext_mux_sel_gpio_num;
	uint32_t ext_mux_sel_delay_us;
	const struct pinctrl_dev_config *pcfg;
};

static void bmc_srst_enable_ctrl(bool enable)
{
#if defined(CONFIG_SOC_AST1080_CM4)
	/* TODO(AST1080 HW bring-up): BMC_SRST not wired on the AST1080 DCSCM
	 * card yet - skip driving it instead of requiring a placeholder
	 * bmc-srst-ctrl-out-gpios devicetree property.
	 */
	ARG_UNUSED(enable);
#else
	int ret;
	const struct gpio_dt_spec srst_gpio =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common),
						bmc_srst_ctrl_out_gpios, 0);

	if (enable) {
		LOG_INF("[PFR->BMC] BMC_SRST Assert[%s %d]", srst_gpio.port->name, srst_gpio.pin);
		gpio_pin_set(srst_gpio.port, srst_gpio.pin, 0);
	} else {
		LOG_INF("[PFR->BMC] BMC_SRST De-assert[%s %d]", srst_gpio.port->name, srst_gpio.pin);
		gpio_pin_set(srst_gpio.port, srst_gpio.pin, 1);
	}

	ret = gpio_pin_configure_dt(&srst_gpio, GPIO_OUTPUT);
	if (ret)
		return;

	k_busy_wait(10000); /* 10ms */
#endif
}

static void bmc_extrst_enable_ctrl(bool enable)
{
	int ret;
	const struct gpio_dt_spec extrst_gpio =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, aspeed_pfr_gpio_common),
						bmc_extrst_ctrl_out_gpios, 0);

	if (enable) {
		LOG_INF("[PFR->BMC] BMC_EXTRST Assert[%s %d]", extrst_gpio.port->name, extrst_gpio.pin);
		gpio_pin_set(extrst_gpio.port, extrst_gpio.pin, 0);
	} else {
		LOG_INF("[PFR->BMC] BMC_EXTRST De-assert[%s %d]", extrst_gpio.port->name, extrst_gpio.pin);
		gpio_pin_set(extrst_gpio.port, extrst_gpio.pin, 1);
	}

	ret = gpio_pin_configure_dt(&extrst_gpio, GPIO_OUTPUT);
	if (ret)
		return;

	k_busy_wait(10000); /* 10ms */
}

int BMCBootHold(void)
{
	const struct device *flash_dev = NULL;

	/* Hold BMC Reset */
	bmc_extrst_enable_ctrl(true);
	// Only pull-up/down SRST in first bootup. Pull-up/down this pin in runtime will affect host
	// VGA function.
	if (first_time_boot)
		bmc_srst_enable_ctrl(true);
	/* config spi monitor as master mode */
	switch_spim_mux(BMC_SPI_MONITOR, SPIM_EXT_MUX_ROT);
	flash_dev = device_get_binding(get_flash_device_name(BMC_SPI));
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind %s", get_flash_device_name(BMC_SPI));
	}
#if defined(CONFIG_BMC_DUAL_FLASH)
	/* config spi monitor as master mode */
	switch_spim_mux(BMC_SPI_MONITOR_2, SPIM_EXT_MUX_ROT);
	flash_dev = device_get_binding(get_flash_device_name(BMC_SPI_2));
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind %s", get_flash_device_name(BMC_SPI_2));
	}
#endif
	LOG_INF("hold BMC");
	return 0;
}

int PCHBootHold(void)
{
	const struct device *flash_dev = NULL;
	const struct platform_gpio_ctrl_ops *gpio_ops = get_platform_gpio_ctrl_ops();

	if (gpio_ops->pch_hold) {
		gpio_ops->pch_hold();
	} else {
		LOG_ERR("Failed to hold PCH");
		return -1;
	}

	/* config spi monitor as master mode */
	switch_spim_mux(PCH_SPI_MONITOR, SPIM_EXT_MUX_ROT);
	flash_dev = device_get_binding(get_flash_device_name(PCH_SPI));
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind %s", get_flash_device_name(PCH_SPI));
	}

#if defined(CONFIG_CPU_DUAL_FLASH)
	/* config spi monitor as master mode */
	switch_spim_mux(PCH_SPI_MONITOR_2, SPIM_EXT_MUX_ROT);
	flash_dev = device_get_binding(get_flash_device_name(PCH_SPI_2));
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind %s", get_flash_device_name(PCH_SPI_2));
	}
#endif
	LOG_INF("hold PCH");
	return 0;
}

int BMCBootRelease(void)
{
	const struct device *dev_m = NULL;
	const struct device *flash_dev = NULL;

	flash_dev = device_get_binding(get_flash_device_name(BMC_SPI));
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind %s", get_flash_device_name(BMC_SPI));
	}
	dev_m = device_get_binding(BMC_SPI_MONITOR);
	aspeed_spi_monitor_sw_rst(dev_m);
	/* config spi monitor as monitor mode */
	switch_spim_mux(BMC_SPI_MONITOR, SPIM_EXT_MUX_BMC_PCH);
#if defined(CONFIG_BMC_DUAL_FLASH)
	flash_dev = device_get_binding(get_flash_device_name(BMC_SPI_2));
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind %s", get_flash_device_name(BMC_SPI_2));
	}
	dev_m = device_get_binding(BMC_SPI_MONITOR_2);
	aspeed_spi_monitor_sw_rst(dev_m);
	/* config spi monitor as monitor mode */
	switch_spim_mux(BMC_SPI_MONITOR_2, SPIM_EXT_MUX_BMC_PCH);
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

	flash_dev = device_get_binding(get_flash_device_name(PCH_SPI));
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind %s", get_flash_device_name(PCH_SPI));
	}
	dev_m = device_get_binding(PCH_SPI_MONITOR);
	aspeed_spi_monitor_sw_rst(dev_m);
	/* config spi monitor as monitor mode */
	switch_spim_mux(PCH_SPI_MONITOR, SPIM_EXT_MUX_BMC_PCH);

#if defined(CONFIG_CPU_DUAL_FLASH)
	flash_dev = device_get_binding(get_flash_device_name(PCH_SPI_2));
	if (flash_dev) {
		spi_nor_rst_by_cmd(flash_dev);
	} else {
		LOG_ERR("Failed to bind %s", get_flash_device_name(PCH_SPI_2));
	}
	dev_m = device_get_binding(PCH_SPI_MONITOR_2);
	aspeed_spi_monitor_sw_rst(dev_m);
	/* config spi monitor as monitor mode */
	switch_spim_mux(PCH_SPI_MONITOR_2, SPIM_EXT_MUX_BMC_PCH);
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

int switch_spim_mux(const char *dev_name, enum spim_ext_mux_sel mux_sel)
{
	const struct device *dev_m = NULL;
	const struct aspeed_spim_config *config;

	dev_m = device_get_binding(dev_name);
	if (dev_m == NULL) {
		printk("%s: unable to bind %s\n", __FUNCTION__, dev_name);
		return -1;
	}
	config = dev_m->config;
	if (config->ext_mux_sel_gpio_num) {
		for (uint32_t i = 0;  i < config->ext_mux_sel_gpio_num; i++) {
			LOG_INF("[%s] EXT_MUXSEL [%s %d] = %d", dev_name,
				config->ext_mux_sel_gpios[i].port->name,
				config->ext_mux_sel_gpios[i].pin,
				(mux_sel == SPIM_EXT_MUX_SEL_1) ? 1 : 0);
		}
	}

	spim_ext_mux_config(dev_m, mux_sel);

	return 0;
}
