/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2026 ASPEED Technology Inc.
 */

#include <zephyr/drivers/cptra.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/misc/aspeed/otp_ast27xx.h>
#include <zephyr/sys/byteorder.h>
#include "cptra_vendor_key.h"
#include "cptra_api.h"
#include <image/caliptra_soc_manifest_v1.h>

#define OTPCAL_VENDOR_KEY_HASH_OFFSET	0x12
#define OTPCAL_VENDOR_KEY_HASH_WORDS	(48U / sizeof(uint16_t))
#define CPTRA_VENDOR_KEY_LEN		1920U
#define CPTRA_CALIPTRA_IMG_HDR_SKIP	8U

LOG_MODULE_REGISTER(cptra_vendor_key, CONFIG_SOC_LOG_LEVEL);

int cptra_verify_vendor_key_hash(const uint8_t *vendor_key, uint32_t key_len)
{
	uint16_t key_hash_words[OTPCAL_VENDOR_KEY_HASH_WORDS];
	uint8_t *key_hash = (uint8_t *)key_hash_words;
	uint8_t cal_key_hash[48];
	int ret;

	for (uint32_t i = 0; i < OTPCAL_VENDOR_KEY_HASH_WORDS; i++) {
		ret = otp_read_cptra(OTPCAL_VENDOR_KEY_HASH_OFFSET + i,
				     &key_hash_words[i]);
		if (ret) {
			/* Treat read failure the same as unprogrammed OTP
			 * (all-zero): skip verification.
			 */
			LOG_WRN("otp_read_cptra failed (word %u, ret:0x%x)",
				i, ret);
			return 0;
		}
	}

	/* Skip verification if OTP vendor key hash is not programmed */
	bool all_zero = true;

	for (uint32_t i = 0; i < OTPCAL_VENDOR_KEY_HASH_WORDS; i++) {
		if (key_hash_words[i] != 0) {
			all_zero = false;
			break;
		}
	}
	if (all_zero) {
		LOG_WRN("Vendor key hash not programmed in OTP, skip verify");
		return 0;
	}

	ret = cptra_sha384((const char *)vendor_key, key_len, cal_key_hash,
			    sizeof(cal_key_hash));
	if (ret) {
		LOG_ERR("cptra_sha384 failed, ret:0x%x", ret);
		return -1;
	}

	if (memcmp(key_hash, cal_key_hash, sizeof(cal_key_hash))) {
		LOG_ERR("Vendor key hash mismatch");
		LOG_HEXDUMP_ERR(key_hash, sizeof(key_hash_words), "OTP hash");
		LOG_HEXDUMP_ERR(cal_key_hash, sizeof(cal_key_hash),
				"Image hash");
		return -1;
	}

	LOG_INF("Vendor key hash verification passed");
	return 0;
}

int cptra_validate_vendor_key_hash(const uint8_t *image_buf,
				    uint32_t image_size)
{
	const struct cptra_flash_header_v1 *flash_hdr;
	const struct cptra_image_info_v1 *image_info;
	uint64_t vendor_key_off;

	if (!image_buf ||
	    image_size < sizeof(*flash_hdr) + sizeof(*image_info)) {
		LOG_ERR("Image buffer too small (%u bytes)", image_size);
		return -EINVAL;
	}

	flash_hdr = (const struct cptra_flash_header_v1 *)image_buf;

	if (flash_hdr->image_count == 0) {
		LOG_ERR("No images in flash header");
		return -EINVAL;
	}

	image_info = (const struct cptra_image_info_v1 *)
			(image_buf + sizeof(*flash_hdr));

	/* image_info[0] is Caliptra FMC+RT; vendor key is at
	 * image_offset + 8 (marker + size skip)
	 */
	vendor_key_off = (uint64_t)image_info[0].image_offset +
			 CPTRA_CALIPTRA_IMG_HDR_SKIP;

	if (vendor_key_off + CPTRA_VENDOR_KEY_LEN > image_size) {
		LOG_ERR("Vendor key region 0x%llx+%u exceeds image size %u",
			(unsigned long long)vendor_key_off,
			CPTRA_VENDOR_KEY_LEN, image_size);
		return -EINVAL;
	}

	return cptra_verify_vendor_key_hash(
		image_buf + (uint32_t)vendor_key_off, CPTRA_VENDOR_KEY_LEN);
}
