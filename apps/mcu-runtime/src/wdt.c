/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <zephyr/device.h>
#include <zephyr/drivers/watchdog.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <scu.h>
#include <wdt.h>

LOG_MODULE_REGISTER(ast_wdt, CONFIG_SOC_FMC_LOG_LEVEL);

#define WDT_MASK_REG_COUNT	5
#define WDT_COUNT		9
#define WDT_INSTANCE_SIZE	0x80

#define WDT_BOOT_NODE		DT_NODELABEL(wdt0)
#define WDT_BOOT_TIMEOUT_MS	30000

static void wdt_writel(uint32_t val, uint32_t addr)
{
	sys_write32(val, addr);
	k_busy_wait(5);
}

int wdt_init(struct ast_chip *chip)
{
	uint32_t idx;
	uint32_t wdt_base_addr;

	if (chip->rev_id) {
		/* ast2700a1 */
		for (idx = 0; idx < WDT_COUNT; idx++) {
			wdt_base_addr = ASPEED_WDT_BASE + idx * WDT_INSTANCE_SIZE;

			/* SoC reset mask */
			wdt_writel(0x8207ff79, wdt_base_addr + WDT_RST_MASK_1);
			wdt_writel(0x000003f6, wdt_base_addr + WDT_RST_MASK_2);
			wdt_writel(0x000093ec, wdt_base_addr + WDT_RST_MASK_3);
			wdt_writel(0x40303803, wdt_base_addr + WDT_RST_MASK_4);
			wdt_writel(0x003a0000, wdt_base_addr + WDT_RST_MASK_5);

			/* SW reset mask */
			wdt_writel(0x8207ff79, wdt_base_addr + WDT_SW_RST_MASK_1);
			wdt_writel(0x000003f6, wdt_base_addr + WDT_SW_RST_MASK_2);
			wdt_writel(0x000093ec, wdt_base_addr + WDT_SW_RST_MASK_3);
			wdt_writel(0x40303803, wdt_base_addr + WDT_SW_RST_MASK_4);
			wdt_writel(0x003a0000, wdt_base_addr + WDT_SW_RST_MASK_5);
		}
	}

	return 0;
}

static void wdt_update_mask(uint32_t reg_addr, uint32_t mask, uint32_t value)
{
	uint32_t reg = sys_read32(reg_addr);

	reg = (reg & ~mask) | value;
	wdt_writel(reg, reg_addr);
}

int wdt_config_reset(struct ast_chip *chip, uint32_t mask_idx,
		     uint32_t mask, uint32_t value)
{
	uint32_t wdt_idx;
	uint32_t wdt_base_addr;

	if (mask_idx >= WDT_MASK_REG_COUNT)
		return -EINVAL;

	for (wdt_idx = 0; wdt_idx < WDT_COUNT; wdt_idx++) {
		wdt_base_addr = ASPEED_WDT_BASE + wdt_idx * WDT_INSTANCE_SIZE;

		wdt_update_mask(wdt_base_addr + WDT_RST_MASK_1 + mask_idx * 4,
				mask, value);
		wdt_update_mask(wdt_base_addr + WDT_SW_RST_MASK_1 + mask_idx * 4,
				mask, value);
	}

	return 0;
}

#if DT_NODE_HAS_STATUS(WDT_BOOT_NODE, okay)
void boot_wdt_enable(void)
{
	const struct device *wdt_dev = DEVICE_DT_GET(WDT_BOOT_NODE);
	const struct wdt_timeout_cfg wdt_cfg = {
		.window.min = 0,
		.window.max = WDT_BOOT_TIMEOUT_MS,
		.callback = NULL,
		.flags = WDT_FLAG_RESET_CPU_CORE,
	};
	int err;

	/*
	 * WDTA is the ABR watchdog. If a previous stage already started it,
	 * leave the boot watchdog alone so that the two do not race to reset
	 * the SoC.
	 */
	if (sys_read32(WDTA_REG + WDT_CTRL) & WDT_ENABLE) {
		LOG_DBG("WDTA is enabled, skip the boot WDT");
		return;
	}

	/*
	 * Recovery mode waits for an image over USB/I2C/I3C/UART, which can
	 * take arbitrarily long, so leave the boot watchdog off as well.
	 */
	if (sys_read32(SCU1_HWSTRAP1) & SCU1_HWSTRAP1_EN_RECOVERY_BOOT) {
		LOG_DBG("Recovery mode is enabled, skip the boot WDT");
		return;
	}

	if (!device_is_ready(wdt_dev)) {
		LOG_ERR("Boot WDT device is not ready");
		return;
	}

	err = wdt_install_timeout(wdt_dev, &wdt_cfg);
	if (err) {
		LOG_ERR("Failed to install boot WDT timeout, err=%d", err);
		return;
	}

	err = wdt_setup(wdt_dev, wdt_cfg.flags);
	if (err)
		LOG_ERR("Failed to start boot WDT, err=%d", err);
}
#else
/* No WDT instance available on this board */
void boot_wdt_enable(void) { }
#endif
