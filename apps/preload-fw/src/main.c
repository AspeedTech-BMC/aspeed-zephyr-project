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
#include "certificate/cert_verify.h"

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
	PFR_DEVID_CERT_INFO *devid_cert_info;
	uint8_t *cert_chain;
	uint32_t cert_chain_len;

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
		// Get device id certificate from internal flash
		devid_cert_info = get_certificate_info();
		if (devid_cert_info == NULL) {
			DEBUG_HALT();
		}

		// If certificate type is CSR, it means device id is not provisioned.
		// Preload firmware should send CSR to HSM for provisioning.
		// Once preload firmware received signed certificate chain from HSM,
		// it should verify certificate chain and replace CSR by certificate
		// chain to complete device id provisioning.
		// If certificate type is certificate, verify the certificate chain.
		// Enable firmware update mailbox commands if certificate chain is
		// verified successfully.
		if (IS_CSR(devid_cert_info)) {
			LOG_INF("Sending DeviceID certificate request to HSM...");
			// TODO:
			// 1. handshake with HSM
			// 2. send CSR to HSM
			// 3. receive certificate chain from HSM
			//
			// DONE:
			// 4. verify certificate chain
			// 5. replace CSR by singed certificate chain
			cert_chain = get_certificate_chain(&cert_chain_len);
			if (verify_certificate(cert_chain, cert_chain_len)) {
				LOG_ERR("Invalid certificate chain");
				cleanup_cert_info();
				DEBUG_HALT();
			}
			LOG_INF("Replace CSR by certificate chain");
			if (write_cert_chain(cert_chain, cert_chain_len)) {
				LOG_ERR("Certificate chain replacement failed");
				cleanup_cert_info();
				DEBUG_HALT();
			}
		} else {
			LOG_INF("Verify certificate chain...");
			cert_chain = devid_cert_info->cert.data;
			cert_chain_len = devid_cert_info->cert.length;
			if (verify_certificate(cert_chain, cert_chain_len)) {
				LOG_ERR("Invalid certificate chain");
				cleanup_cert_info();
				DEBUG_HALT();
			}

			cleanup_cert_info();
#if defined(CONFIG_PFR_SW_MAILBOX)
			init_sw_mailbox();
#endif
			BMCBootRelease();
			PCHBootRelease();
			LOG_INF("Ready for ROT firmware replacement");
		}
	} else {
		// Secure Boot is not enabled
		// Perform the following process
		// TODO:
		// 1. Update OTP image
		// 2. Generate vault key
		// 3. Enable secure boot
		// 4. Enable CDI
		// 5. Erase OTP image
#if 0
		dev_entropy = device_get_binding(DT_LABEL(DT_NODELABEL(rng)));
		if (!dev_entropy) {
			LOG_ERR("Hardware random number generator not found");
			DEBUG_HALT();
		}

		entropy_get_entropy(dev_entropy, vault_key_buf, sizeof(vault_key_buf));
		LOG_HEXDUMP_INF(vault_key_buf, sizeof(vault_key_buf), "vault key:");
#endif
	}

#if defined(CONFIG_ABR_FLOW_CTRL_ASPEED)
	// Remove this if abr is not enabled.
	disable_abr_wdt();
#endif

}
