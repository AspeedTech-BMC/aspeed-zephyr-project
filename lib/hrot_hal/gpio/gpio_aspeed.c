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

static char *GPIO_Devices_List[6] = {
	"GPIO0_A_D",
	"GPIO0_E_H",
	"GPIO0_I_L",
	"GPIO0_M_P",
	"GPIO0_Q_T",
	"GPIO0_U_V",
};

static void GPIO_dump_buf(uint8_t *buf, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++) {
		LOG_INF("%02x ", buf[i]);
		if (i % 16 == 15)
			LOG_INF("\n");
	}
	LOG_INF("\n");
}

int BMCBootHold(void)
{
	const struct device *gpio_dev = NULL;
	const struct device *dev_m = NULL;

	dev_m = device_get_binding(BMC_SPI_MONITOR);
	spim_rst_flash(dev_m, 1000);
	spim_passthrough_config(dev_m, 0, false);
#if defined(CONFIG_ASPEED_DC_SCM)
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_SEL_1);
	pfr_bmc_srst_enable_ctrl(true);
	pfr_bmc_extrst_enable_ctrl(true);
#else
	/* config all spi monitor as master mode */
	spim_ext_mux_config(dev_m, 1);
	/* GPIOM5 */
	gpio_dev = device_get_binding("GPIO0_M_P");

	if (gpio_dev == NULL) {
		LOG_INF("[%d]Fail to get GPIO0_M_P", __LINE__);
		return -1;
	}

	gpio_pin_configure(gpio_dev, BMC_SRST, GPIO_OUTPUT);

	k_busy_wait(10000); /* 10ms */

	gpio_pin_set(gpio_dev, BMC_SRST, 0);

	k_busy_wait(10000); /* 10ms */

#endif
	return 0;
}

int PCHBootHold(void)
{
	const struct device *gpio_dev = NULL;
	const struct device *dev_m = NULL;

	dev_m = device_get_binding(PCH_SPI_MONITOR);
	spim_rst_flash(dev_m, 1000);
	spim_passthrough_config(dev_m, 0, false);
#if defined(CONFIG_ASPEED_DC_SCM)
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_SEL_1);
	pfr_pch_rst_enable_ctrl(true);
#else
	/* config all spi monitor as master mode */
	spim_ext_mux_config(dev_m, 1);
	/* GPIOM5 */
	gpio_dev = device_get_binding("GPIO0_M_P");

	if (gpio_dev == NULL) {
		LOG_INF("[%d]Fail to get GPIO0_M_P", __LINE__);
		return -1;
	}

	gpio_pin_configure(gpio_dev, CPU0_RST, GPIO_OUTPUT);

	k_busy_wait(10000); /* 10ms */

	gpio_pin_set(gpio_dev, CPU0_RST, 0);

	k_busy_wait(10000); /* 10ms */

#endif
	return 0;
}

int BMCBootRelease(void)
{
	const struct device *gpio_dev = NULL;
	const struct device *dev_m = NULL;

	dev_m = device_get_binding(BMC_SPI_MONITOR);
	spim_rst_flash(dev_m, 1000);
	spim_passthrough_config(dev_m, 0, false);
#if defined(CONFIG_ASPEED_DC_SCM)
	LOG_INF("release BMC");
	aspeed_spi_monitor_sw_rst(dev_m);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_SEL_0);
	pfr_bmc_srst_enable_ctrl(false);
	pfr_bmc_extrst_enable_ctrl(false);
#else
	/* config spim as SPI monitor */
	spim_ext_mux_config(dev_m, 0);

	/* GPIOM5 */
	gpio_dev = device_get_binding("GPIO0_M_P");

	if (gpio_dev == NULL) {
		LOG_INF("[%d]Fail to get GPIO0_M_P", __LINE__);
		return -1;
	}

	gpio_pin_configure(gpio_dev, BMC_SRST, GPIO_OUTPUT);

	k_busy_wait(20000); /* 10ms */

	gpio_pin_set(gpio_dev, BMC_SRST, 1);

	k_busy_wait(20000); /* 10ms */
#endif
	return 0;
}

int PCHBootRelease(void)
{
	const struct device *gpio_dev = NULL;
	const struct device *dev_m = NULL;

	dev_m = device_get_binding(PCH_SPI_MONITOR);
	spim_rst_flash(dev_m, 1000);
	spim_passthrough_config(dev_m, 0, false);
#if defined(CONFIG_ASPEED_DC_SCM)
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_SEL_0);
	pfr_pch_rst_enable_ctrl(false);
#else
	/* config spim as SPI monitor */
	spim_ext_mux_config(dev_m, 0);
	/* GPIOM5 */
	gpio_dev = device_get_binding("GPIO0_M_P");

	if (gpio_dev == NULL) {
		LOG_INF("[%d]Fail to get GPIO0_M_P", __LINE__);
		return -1;
	}

	gpio_pin_configure(gpio_dev, CPU0_RST, GPIO_OUTPUT);

	k_busy_wait(10000); /* 10ms */

	gpio_pin_set(gpio_dev, CPU0_RST, 1);

	k_busy_wait(10000); /* 10ms */

#endif
	return 0;
}

