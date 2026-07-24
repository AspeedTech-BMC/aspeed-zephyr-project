/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/drivers/flash.h>
#include <zephyr/drivers/spi_nor.h>
#include <spi_filter/spim_util.h>
#include <gpio/gpio_aspeed.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/kernel.h>

#if defined(CONFIG_SOC_AST1080_CM4)
#include <zephyr/drivers/misc/aspeed/ast2700_spim.h>
#endif

void SPI_Monitor_Enable(const char *dev_name, bool enabled)
{
	const struct device *dev_m = NULL;

	dev_m = device_get_binding(dev_name);
	if (dev_m == NULL) {
		printk("%s: unable to bind %s\n", __FUNCTION__, dev_name);
		return ;
	}
	spim_monitor_enable(dev_m, enabled);
}

int Set_SPI_Filter_RW_Region(const char *dev_name, enum addr_priv_rw_select rw_select, enum addr_priv_op op, mm_reg_t addr, uint32_t len)
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

#if defined(CONFIG_SOC_AST1080_CM4)
/*
 * AST1080's SPI monitor uses the AST2700-style address-privilege table:
 * one HW slot per call, carrying both the read- and write-deny bits at
 * once, and no slot at all for the "allow" case (default state is
 * allow-all). Set_SPI_Filter_RW_Region()'s per-direction ENABLE/DISABLE
 * model has no equivalent here, so callers report a region's read/write
 * policy through this single explicit call instead.
 *
 * apply_pfm_protection() re-arms the same regions on every BmcOnlyReset/
 * PchOnlyReset/checkpoint event, not just once at boot. Callers must clear
 * the device's table with SPI_Filter_Remove_All() first, or re-arming an
 * already-configured region hits the HW table's overlay check and fails.
 */
int Set_SPI_Filter_Deny_Region(const char *dev_name, bool deny_read, bool deny_write,
		mm_reg_t addr, uint32_t len)
{
	const struct device *dev_m;
	uint32_t attr = 0;

	if (!deny_read && !deny_write)
		return 0;

	dev_m = device_get_binding(dev_name);
	if (dev_m == NULL) {
		printk("%s: unable to bind %s\n", __FUNCTION__, dev_name);
		return -1;
	}

	if (deny_read)
		attr |= FLAG_ADDR_PRIV_READ_DIS;
	if (deny_write)
		attr |= FLAG_ADDR_PRIV_WRITE_DIS;

	return ast2700_address_privilege_config(dev_m, addr, len, attr);
}

void SPI_Filter_Remove_All(const char *dev_name)
{
	const struct device *dev_m;

	dev_m = device_get_binding(dev_name);
	if (dev_m == NULL) {
		printk("%s: unable to bind %s\n", __FUNCTION__, dev_name);
		return;
	}

	spim_addr_priv_remove_all(dev_m);
}
#endif
