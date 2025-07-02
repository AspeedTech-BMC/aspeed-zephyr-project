/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <manifest.h>

#include <zephyr/crypto/crypto.h>
#include <zephyr/crypto/hash.h>
#include <zephyr/drivers/cptra.h>
#include <zephyr/logging/log.h>

#define CPTRA_HASH_DRV_NAME DEVICE_DT_NAME(DT_INST(0, aspeed_cptra_sha))
#define CPTRA_MISC_DRV_NAME DEVICE_DT_NAME(DT_INST(0, aspeed_cptra_misc))

LOG_MODULE_REGISTER(cptra_manifest_sig, CONFIG_LOG_DEFAULT_LEVEL);

static struct cptra_set_auth_manifest_ia input = {0};

static void cptra_preamble_convert(struct cptra_manifest_preamble *preamble,
				   struct cptra_manifest_aspeed_preamble *aspeed_preamble)
{
	preamble->manifest_marker = aspeed_preamble->manifest_marker;
	preamble->preamble_size = aspeed_preamble->preamble_size;
	preamble->manifest_version = aspeed_preamble->manifest_version;
	preamble->manifest_flags = aspeed_preamble->manifest_flags;
	memcpy(preamble->manifest_vendor_ecc384_key, aspeed_preamble->manifest_vendor_ecc384_key,
	       sizeof(preamble->manifest_vendor_ecc384_key));
	memcpy(preamble->manifest_vendor_lms_key, aspeed_preamble->manifest_vendor_lms_key,
	       sizeof(preamble->manifest_vendor_lms_key));
	memcpy(preamble->manifest_vendor_ecc384_sig, aspeed_preamble->manifest_vendor_ecc384_sig,
	       sizeof(preamble->manifest_vendor_ecc384_sig));
	memcpy(preamble->manifest_vendor_LMS_sig, aspeed_preamble->manifest_vendor_LMS_sig,
	       sizeof(preamble->manifest_vendor_LMS_sig));
	memcpy(preamble->manifest_owner_ecc384_key, aspeed_preamble->manifest_owner_ecc384_key,
	       sizeof(preamble->manifest_owner_ecc384_key));
	memcpy(preamble->manifest_owner_lms_key, aspeed_preamble->manifest_owner_lms_key,
	       sizeof(preamble->manifest_owner_lms_key));
	memcpy(preamble->manifest_owner_ecc384_sig, aspeed_preamble->manifest_owner_ecc384_sig,
	       sizeof(preamble->manifest_owner_ecc384_sig));
	memcpy(preamble->manifest_owner_LMS_sig, aspeed_preamble->manifest_owner_LMS_sig,
	       sizeof(preamble->manifest_owner_LMS_sig));
	memcpy(preamble->metadata_vendor_ecc384_sig, aspeed_preamble->metadata_vendor_ecc384_sig,
	       sizeof(preamble->metadata_vendor_ecc384_sig));
	memcpy(preamble->metadata_vendor_LMS_sig, aspeed_preamble->metadata_vendor_LMS_sig,
	       sizeof(preamble->metadata_vendor_LMS_sig));
	memcpy(preamble->metadata_owner_ecc384_sig, aspeed_preamble->metadata_owner_ecc384_sig,
	       sizeof(preamble->metadata_owner_ecc384_sig));
	memcpy(preamble->metadata_owner_LMS_sig, aspeed_preamble->metadata_owner_LMS_sig,
	       sizeof(preamble->metadata_owner_LMS_sig));
}

static int cptra_manifest_sha384(uint8_t *img, uint32_t size, uint8_t *digest)
{
	struct hash_ctx ini = {0};
	struct hash_pkt pkt = {0};
	const struct device *dev = device_get_binding(CPTRA_HASH_DRV_NAME);

	ini.flags = crypto_query_hwcaps(dev);
	pkt.in_buf = (uint8_t *)img;
	pkt.in_len = size;
	pkt.out_buf = digest;

	if (hash_begin_session(dev, &ini, CRYPTO_HASH_ALGO_SHA384) || hash_update(&ini, &pkt) ||
	    hash_compute(&ini, &pkt) || hash_free_session(dev, &ini)) {
		LOG_ERR("cptra sha384 calculate fail.");
		return CPTRA_ERR_SHA384_CAL;
	}

	return CPTRA_SUCCESS;
}

int cptra_verify_soc_manifest(struct cptra_soc_manifest *manifest)
{
	struct cptra_set_auth_manifest_oa output = {0};
	const struct device *dev = device_get_binding(CPTRA_MISC_DRV_NAME);

	input.manifest_size = sizeof(struct cptra_manifest_preamble) + sizeof(manifest->ime_count) +
			      sizeof(manifest->imc);
	input.metadata_entry_entry_count = manifest->ime_count;

	/* Convert aspeed preamble format to caliptra preamble format*/
	cptra_preamble_convert(&(input.preamble), &(manifest->preamble));
	memcpy(&(input.metadata_entries), manifest->imc, sizeof(manifest->imc));

	return caliptra_set_auth_manifest(dev, &input, &output);
}

int cptra_verify_image(uint8_t *img, uint32_t img_size, struct cptra_manifest_ime *ime)
{
	int ret = 0;
	struct cptra_authorize_and_stash_ia input = {0};
	struct cptra_authorize_and_stash_oa output = {0};
	const struct device *dev = device_get_binding(CPTRA_MISC_DRV_NAME);

	ret = cptra_manifest_sha384(img, img_size, (uint8_t *)&input.measurement);
	if (ret)
		return CPTRA_ERR_SHA384_CAL;

	*input.fw_id = ime->fw_id;
	input.source = ime->flags & 0x3;
	ret = caliptra_authorize_and_stash(dev, &input, &output);
	if (ret)
		return CPTRA_ERR_IMAGE_VFY;

	return CPTRA_SUCCESS;
}
