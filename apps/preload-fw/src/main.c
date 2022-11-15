/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <zephyr.h>
#include <build_config.h>
#include <drivers/entropy.h>
#include <drivers/misc/aspeed/abr_aspeed.h>
#include "gpio/gpio_ctrl.h"
#include "sw_mailbox/sw_mailbox.h"

LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

#define DEBUG_HALT() {				  \
		volatile int halt = 1;		  \
		while (halt) {			  \
			__asm__ volatile ("nop"); \
		}				  \
}

#define SCU_BASE                     0x7e6e2000
#define SCU_HW_STRAP                 SCU_BASE + 0x51c
#define SCU_OTP_STRAP_EN             BIT(1)
#define SCU_LOW_SECURITY_EN          BIT(0)
#define SEC_BASE                     0x7e6f2000

extern void aspeed_print_sysrst_info(void);

uint8_t vault_key_buf[64];
void main(void)
{
	uint32_t secure_boot_reg;
	BMCBootHold();
	PCHBootHold();

	LOG_INF("*** ASPEED Preload FW version v%02d.%02d Board:%s ***", PROJECT_VERSION_MAJOR, PROJECT_VERSION_MINOR, CONFIG_BOARD);
	aspeed_print_sysrst_info();

	secure_boot_reg = sys_read32(SCU_HW_STRAP);
#ifdef SECUREBOOT_ENABLED_BY_OTP
	if (secure_boot_reg & SCU_OTP_STRAP_EN) {
#else
	if (secure_boot_reg & SCU_LOW_SECURITY_EN) {
#endif
		// Secure boot is enabled
		// TODO: Check devid certificate type

#if defined(CONFIG_PFR_SW_MAILBOX)
		init_sw_mailbox();
#endif

		BMCBootRelease();
		PCHBootRelease();
	} else {
		// Secure Boot is not enabled
		// Perform the following process
		// 1. Update OTP image
		// 2. Generate vault key
		// 3. Enable secure boot
		// 4. Enable CDI
		// 5. Erase OTP image
	}

#if 0
	dev_entropy = device_get_binding(DT_LABEL(DT_NODELABEL(rng)));
	if (!dev_entropy) {
		return;
	}

	entropy_get_entropy(dev_entropy, vault_key_buf, sizeof(vault_key_buf));
	LOG_HEXDUMP_INF(vault_key_buf, sizeof(vault_key_buf), "vault key:");
#endif

#if defined(CONFIG_ABR_FLOW_CTRL_ASPEED)
	// Remove this if abr is not enabled.
	disable_abr_wdt();
#endif
}
