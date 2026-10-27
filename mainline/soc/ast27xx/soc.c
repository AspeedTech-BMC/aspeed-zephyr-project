/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2023 ASPEED Technology Inc.
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <stdint.h>
#include <zephyr/device.h>
#include <soc.h>
#include "scu1_clk_lock.h"

#if IS_ENABLED(CONFIG_WDT_ASPEED) && DT_NODE_HAS_STATUS(DT_NODELABEL(wdt0), okay)
void aspeed_wdt_reboot_device(const struct device *dev, int type);

void sys_arch_reboot(int type)
{
	const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(wdt0));

	aspeed_wdt_reboot_device(dev, type);
}
#endif

/* DMA address translation */
uint64_t ast27xx_soc_virt_addr_to_phy_addr(uintptr_t addr)
{
	if (addr < 0x80000000) {
		return addr;
	}

	return (uint64_t)(addr & ~0x80000000) | 0x400000000ULL;
}

uintptr_t ast27xx_soc_phy_addr_to_virt_addr(uint64_t addr)
{
	if (addr < 0x400000000) {
		return addr;
	}

	return (uintptr_t)(addr - 0x400000000ULL) | 0x80000000UL;
}

static int soc_init(void)
{
	ast27xx_scu1_clk_lock();

	return 0;
}

SYS_INIT(soc_init, PRE_KERNEL_1, 0);
