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

	input.manifest_size = sizeof(struct cptra_soc_manifest);
	input.metadata_entry_entry_count = manifest->ime_count;
	memcpy(&(input.preamble), &(manifest->preamble), sizeof(manifest->preamble));
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
