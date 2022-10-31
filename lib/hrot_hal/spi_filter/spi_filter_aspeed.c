/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <drivers/flash.h>
#include <drivers/spi_nor.h>
#include <spi_filter/spi_filter_aspeed.h>
#include <gpio/gpio_aspeed.h>
#include <kernel.h>
#include <sys/util.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr.h>

void SPI_Monitor_Enable(char *dev_name, bool enabled)
{
	const struct device *dev_m = NULL;

	dev_m = device_get_binding(dev_name);
	if (dev_m == NULL) {
		printk("%s: unable to bind %s\n", __FUNCTION__, dev_name);
		return ;
	}
	spim_monitor_enable(dev_m, enabled);
}

int Set_SPI_Filter_RW_Region(char *dev_name, enum addr_priv_rw_select rw_select, enum addr_priv_op op, mm_reg_t addr, uint32_t len)
{
	int ret = 0;
	const struct device *dev_m = NULL;

	dev_m = device_get_binding(dev_name);
	if (dev_m == NULL) {
		printk("%s: unable to bind %s\n", __FUNCTION__, dev_name);
		return -1;
	}
	ret = spim_address_privilege_config(dev_m, rw_select, op, addr, len);

	return ret;
}
