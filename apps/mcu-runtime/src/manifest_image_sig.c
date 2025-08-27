/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <ast_loader.h>
#include <manifest.h>

#include <zephyr/sys/byteorder.h>
#include <zephyr/crypto/crypto.h>
#include <zephyr/crypto/ecdsa.h>
#include <zephyr/crypto/hash.h>
#include <zephyr/crypto/lms.h>
#include <zephyr/drivers/cptra.h>
#include <zephyr/logging/log.h>

#define CPTRA_HASH_DRV_NAME DEVICE_DT_NAME(DT_INST(0, aspeed_cptra_sha))
#define CPTRA_ECDSA_DRV_NAME DEVICE_DT_NAME(DT_INST(0, aspeed_cptra_ecdsa))
#define CPTRA_LMS_DRV_NAME   DEVICE_DT_NAME(DT_INST(0, aspeed_cptra_lms))
#define CPTRA_MISC_DRV_NAME DEVICE_DT_NAME(DT_INST(0, aspeed_cptra_misc))

LOG_MODULE_REGISTER(cptra_manifest_sig, CONFIG_LOG_DEFAULT_LEVEL);

static struct cptra_set_auth_manifest_ia input = {0};

static int cptra_memcpy_to_be(uint32_t *dest, uint32_t *src, uint32_t size)
{
	int i = 0;

	if (dest == NULL || src == NULL || size % sizeof(uint32_t) != 0)
		return CPTRA_ERR_INVALID_PARAMETER;

	memcpy(dest, src, size);
	for (i = 0; i < size / sizeof(uint32_t); i++)
		dest[i] = sys_cpu_to_be32(dest[i]);

	return CPTRA_SUCCESS;
}

static int cptra_get_cptra_own_x_pubk(uint32_t *x_key)
{
	return ast_loader_read(x_key, CPTRA_OWNER_CPTRA_ECC_PUBK_X_OFFSET, 48);
}

static int cptra_get_cptra_own_y_pubk(uint32_t *y_key)
{
	return ast_loader_read(y_key, CPTRA_OWNER_CPTRA_ECC_PUBK_Y_OFFSET, 48);
}

static int cptra_get_cptra_own_lms_pubk(struct lms_pub_key *pubk)
{
	return ast_loader_read((uint32_t *)pubk, CPTRA_OWNER_CPTRA_LMS_PUBK_OFFSET,
			       sizeof(struct lms_pub_key));
}

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

static int cptra_manifest_ecdsa384(uint8_t *data, uint32_t data_size, uint32_t *x, uint32_t *y,
				   uint32_t *r, uint32_t *s)
{
	uint8_t digest[48] = {0};
	uint32_t r_be[12] = {0};
	uint32_t s_be[12] = {0};
	uint32_t x_be[12] = {0};
	uint32_t y_be[12] = {0};
	int ret = 0;
	struct ecdsa_ctx ini = {0};
	struct ecdsa_pkt pkt = {CPTRA_ECDSA384_VFY_PKT(r_be, s_be)};
	struct ecdsa_key ek = {CPTRA_ECDSA384_NIST_P384_CURVE(x_be, y_be)};
	const struct device *dev = device_get_binding(CPTRA_ECDSA_DRV_NAME);

	/* Copy the pubk and sig and convert to big endian */
	cptra_memcpy_to_be(r_be, r, sizeof(r_be));
	cptra_memcpy_to_be(s_be, s, sizeof(s_be));
	cptra_memcpy_to_be(x_be, x, sizeof(x_be));
	cptra_memcpy_to_be(y_be, y, sizeof(y_be));

	ret = cptra_manifest_sha384(data, data_size, digest);
	if (ret)
		return ret;

	ret = ecdsa_begin_session(dev, &ini, &ek);
	if (ret)
		return ret;

	ret = ecdsa_verify(&ini, &pkt);

	ecdsa_free_session(dev, &ini);

	return ret;
}

static int cptra_manifest_lms(uint8_t *data, uint32_t data_size, struct lms_pub_key *pubk,
			      struct lms_signature *sig)
{
	uint8_t digest[48] = {0};
	int ret = 0;
	struct lms_ctx ctx = {0};
	struct lms_pkt pkt = {0};
	const struct device *dev = device_get_binding(CPTRA_LMS_DRV_NAME);

	/* Setup the to be verified signature */
	pkt.sig.q = sys_cpu_to_be32(sig->q);
	pkt.sig.tree_type = sys_cpu_to_be32(sig->tree_type);
	memcpy(pkt.sig.ots, sig->ots, LMS_SIG_OTS_LEN);
	memcpy(pkt.sig.tree_path, sig->tree_path, LMS_SIG_TREE_PATH);

	ret = cptra_manifest_sha384(data, data_size, digest);
	if (ret)
		return ret;

	ret = lms_begin_session(dev, &ctx, pubk);
	if (ret)
		return ret;

	ret = lms_verify(&ctx, &pkt);

	lms_free_session(dev, &ctx);

	return ret;
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

#define CPTRA_SOC_MANIFEST_VER (0)
int cptra_verify_soc_manifest_ver(struct cptra_soc_manifest *manifest)
{
	static uint32_t ecc_pubk_x[12] = {0};
	static uint32_t ecc_pubk_y[12] = {0};
	struct lms_pub_key lms_pubk = {0};
	struct cptra_manifest_aspeed_svn data = {0};
	struct cptra_manifest_aspeed_preamble *preamble = &(manifest->preamble);

	data.ver = preamble->manifest_version;
	data.sec_ver = preamble->manifest_sec_version;
	data.flags = preamble->manifest_flags;
	memcpy(&data.manifest_owner_ecc384_key, preamble->manifest_owner_ecc384_key,
	       sizeof(data.manifest_owner_ecc384_key));
	memcpy(&data.manifest_owner_lms_key, preamble->manifest_owner_lms_key,
	       sizeof(data.manifest_owner_lms_key));

	cptra_get_cptra_own_x_pubk(ecc_pubk_x);
	cptra_get_cptra_own_y_pubk(ecc_pubk_y);
	if (cptra_manifest_ecdsa384((uint8_t *)&data, sizeof(data), ecc_pubk_x, ecc_pubk_y,
				    &(preamble->manifest_owner_svn_ecc384_sig[0]),
				    &(preamble->manifest_owner_svn_ecc384_sig[12])))
		return CPTRA_ERR_SOC_MANIFEST_ECC_SVN_VFY;

	cptra_get_cptra_own_lms_pubk(&lms_pubk);
	if (cptra_manifest_lms((uint8_t *)&data, sizeof(data), &lms_pubk,
			       (struct lms_signature *)preamble->manifest_owner_svn_LMS_sig))
		return CPTRA_ERR_SOC_MANIFEST_LMS_SVN_VFY;

	if (data.sec_ver < CPTRA_SOC_MANIFEST_VER)
		return CPTRA_ERR_SOC_MANIFEST_VER_MISMATCH;

	return CPTRA_SUCCESS;
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
		return CPTRA_ERR_IMAGE_VFY_MBOX_ERROR;

	/* Mailbox error handler */
	switch (output.auth_req_result) {
	case AUTHORIZE_IMAGE:
		return CPTRA_SUCCESS;
	case IMAGE_HASH_MISMATCH:
		return CPTRA_ERR_IMAGE_VFY_HASH_MISMATCH;
	case IMAGE_NOT_AUTHORIZED:
		return CPTRA_ERR_IMAGE_VFY_FWID_MISMATCH;
	default:
		return CPTRA_ERR_IMAGE_VFY_UNKNOWN_ERROR;
	}
}
