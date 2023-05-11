/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <zephyr.h>
#include <logging/log.h>
#include <storage/flash_map.h>
#include <drivers/misc/aspeed/abr_aspeed.h>
#include "cert_verify.h"
#include "cert_prov.h"
#include "otp/otp_utils.h"
#include "sw_mailbox/sw_mailbox.h"

LOG_MODULE_REGISTER(prov, CONFIG_LOG_DEFAULT_LEVEL);
PFR_DEVID_CERT_INFO devid_cert_info;
uint8_t cert_chain[CERT_CHAIN_SIZE];

PROV_STATUS cert_provision(void)
{
	uint32_t cert_chain_len;
	enum otp_status otp_rc;
	bool is_secureboot_en;

	is_secureboot_en = is_otp_secureboot_en(&otp_rc);
	if (otp_rc) {
		//DEBUG_HALT();
		goto out;
	}

	if (is_secureboot_en) {
		// Secure boot is enabled
		// Get device id certificate from internal flash
		LOG_INF("Secure boot is enabled, handling certificate");
		if (get_certificate_info(&devid_cert_info, sizeof(devid_cert_info))) {
			//DEBUG_HALT();
			LOG_ERR("Failed to get certificate!");
			goto out;
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
			get_certificate_chain(cert_chain, &cert_chain_len);
			LOG_INF("Received certificate chain from HSM, verifying");
			if (verify_certificate(cert_chain, cert_chain_len)) {
				LOG_ERR("Invalid certificate chain");
				cleanup_cert_info();
				//DEBUG_HALT();
				goto out;
			}
			LOG_INF("Replace CSR by certificate chain");
			if (write_cert_chain(cert_chain, cert_chain_len)) {
				LOG_ERR("Certificate chain replacement failed");
				cleanup_cert_info();
				//DEBUG_HALT();
				goto out;
			}
			LOG_INF("Certificate chain is updated successfully");
#if defined(CONFIG_ODM_ROT_REPLACEMENT)
			// Erase aspeed preload firmware
			// 1st-slot firmware will be replaced by 2nd-slot firmeware in mcuboot
			const struct flash_area *fa;
			if (flash_area_open(FLASH_AREA_ID(active), &fa)) {
				LOG_ERR("Failed to find active fw region");
				goto out;
			}
			flash_area_erase(fa, 0, fa->fa_size);
#endif
		} else {
			LOG_INF("Verify certificate chain...");
			if (verify_certificate(devid_cert_info.cert.data,
						devid_cert_info.cert.length)) {
				LOG_ERR("Invalid certificate chain");
				cleanup_cert_info();
				//DEBUG_HALT();
				goto out;
			}

			cleanup_cert_info();
#if defined(CONFIG_PFR_SW_MAILBOX)
			init_sw_mailbox();
#endif
			LOG_INF("Ready for ROT firmware replacement");
			return PROV_ROT_UPDATE;
		}
	} else {
		// Secure Boot is not enabled
		// Write necessary info to OTP memory
		//
		// otp_prog() does the following process:
		//   1. Update OTP image from flash to OTP memory
		//   2. Generate vault key
		//   3. Enable secure boot
		//   4. Enable CDI
		//   5. Erase OTP image in flash
		if (otp_prog(OTP_IMAGE_ADDR)) {
			LOG_ERR("OTP image update failed");
			goto out;
		}
	}

#if !defined(CONFIG_DEVID_CERT_PROVISIONING)
	// Erase aspeed preload firmware
	// 1st-slot firmware will be replaced by 2nd-slot firmeware in mcuboot
	const struct flash_area *fa;
	if (flash_area_open(FLASH_AREA_ID(active), &fa)) {
	}
	flash_area_erase(fa, 0, fa->fa_size);
#endif
	return PROV_DONE;

out:
	memset(cert_chain, 0, sizeof(cert_chain));
	memset(&devid_cert_info, 0, sizeof(devid_cert_info));
#if defined(CONFIG_ABR_FLOW_CTRL_ASPEED)
	// Remove this if abr is not enabled.
	disable_abr_wdt();
	return PROV_FAIL;
#endif
}
