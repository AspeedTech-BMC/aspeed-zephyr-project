/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <zephyr/logging/log.h>
#include "mbedtls/lms.h"
#include "AspeedStateMachine/common_smc.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_verification.h"
#include "intel_pfr_sig_scheme.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

static void clear_key(struct pfr_pubkey *pubkey)
{
	pubkey->lms_key_len = 0;
	memset(pubkey->lms_key, 0, sizeof(pubkey->lms_key));
}

static int load_key(struct pfr_manifest *manifest, const KEY_ENTRY_lms *entry)
{
	struct pfr_pubkey *pubkey = manifest->verification->pubkey;
	int len = entry->keylen - CONFIG_LMS_SIGN_SERIAL_OFFSET;

	if (len <= 0 || len > sizeof(pubkey->lms_key)) {
		LOG_ERR("Invalid LMS public key length, %d", entry->keylen);
		return Failure;
	}

	pubkey->lms_key_len = len;
	memcpy(pubkey->lms_key, &entry->pubkey[CONFIG_LMS_SIGN_SERIAL_OFFSET], len);

	return Success;
}

static int verify_sig(struct pfr_manifest *manifest, const uint8_t *sig, int siglen, bool csk)
{
	struct pfr_pubkey *pubkey = manifest->verification->pubkey;
	uint32_t hash_length = intel_pfr_hash_length(manifest->sig_scheme->hash_type);
	mbedtls_lms_public_t pub_ctx;
	int ret;

	if (siglen <= CONFIG_LMS_SIGN_SERIAL_OFFSET) {
		LOG_ERR("Invalid LMS signature length, %d", siglen);
		return Failure;
	}

	mbedtls_lms_public_init(&pub_ctx);
	ret = mbedtls_lms_import_public_key(&pub_ctx, pubkey->lms_key, pubkey->lms_key_len);
	if (ret != 0) {
		LOG_ERR("import public key failed, ret = %x", -ret);
	} else {
		ret = mbedtls_lms_verify(&pub_ctx, manifest->pfr_hash->hash_out, hash_length,
					 sig + CONFIG_LMS_SIGN_SERIAL_OFFSET,
					 siglen - CONFIG_LMS_SIGN_SERIAL_OFFSET);
		if (ret != 0) {
			if (csk)
				LOG_ERR("verify failed, ret = %x, siglen = %d, lms_verify_pubkey_len = %d, hash_length = %d\n",
					ret, siglen - CONFIG_LMS_SIGN_SERIAL_OFFSET, pubkey->lms_key_len, hash_length);
			else
				LOG_ERR("verify failed, ret = %x, siglen = %d\n", ret, siglen - 4);
		}
	}
	mbedtls_lms_public_free(&pub_ctx);

	if (ret != 0) {
		clear_key(pubkey);
		return Failure;
	}

	return Success;
}

static int lms_load_root_key(struct pfr_manifest *manifest, uint32_t addr)
{
	KEY_ENTRY_lms root;

	if (pfr_spi_read(manifest->image_type, addr, sizeof(root), (uint8_t *)&root)) {
		LOG_ERR("Block1 Root Entry: Flash read data failed");
		return Failure;
	}

	if (root.keylen <= 0 || root.keylen > sizeof(root.pubkey)) {
		LOG_ERR("Block1 Root Entry: Invalid LMS public key length, %d", root.keylen);
		return Failure;
	}

	if (intel_pfr_sig_hash(manifest, root.pubkey, root.keylen)) {
		LOG_ERR("Block1 Root Entry: Get hash failed");
		return Failure;
	}

	if (intel_pfr_check_root_key_hash(manifest->pfr_hash->hash_out,
			intel_pfr_hash_length(manifest->sig_scheme->hash_type), root.pubkey, root.keylen))
		return Failure;

	return load_key(manifest, &root);
}

static int lms_verify_csk(struct pfr_manifest *manifest, uint32_t addr)
{
	static CSKENTRY_lms csk;
	int i;

	if (pfr_spi_read(manifest->image_type, addr, sizeof(csk), (uint8_t *)&csk)) {
		LOG_ERR("Block1 CSK Entry: Flash read data failed");
		return Failure;
	}

	if (intel_pfr_check_sig_magic(manifest->sig_scheme, csk.CskSignatureMagic, true))
		return Failure;

	if (intel_pfr_check_csk_permission(manifest, csk.CskEntryInitial.KeyPermission))
		return Failure;

	for (i = 0; i < sizeof(csk.CskEntryInitial.Reserved); i++) {
		if (csk.CskEntryInitial.Reserved[i] != 0) {
			LOG_ERR("Block1 CSK Entry: reserved data failed");
			return Failure;
		}
	}

	if (csk.siglen > sizeof(csk.CskSignature)) {
		LOG_ERR("Block1 CSK Entry: Invalid signature length, %d", csk.siglen);
		return Failure;
	}

	if (intel_pfr_sig_hash(manifest, (uint8_t *)&csk.CskEntryInitial.PubCurveMagic,
			       sizeof(KEY_ENTRY_lms) - sizeof(uint32_t))) {
		LOG_ERR("Block1 CSK Entry: Get hash failed");
		return Failure;
	}

	if (verify_sig(manifest, csk.CskSignature, csk.siglen, true))
		return Failure;

	return load_key(manifest, &csk.CskEntryInitial);
}

static int lms_verify_block0(struct pfr_manifest *manifest, uint32_t addr)
{
	static BLOCK0ENTRY_lms entry;

	if (pfr_spi_read(manifest->image_type, addr, sizeof(entry), (uint8_t *)&entry)) {
		LOG_ERR("Block1 Block0 Entry: Flash read data failed");
		return Failure;
	}

	if (intel_pfr_check_sig_magic(manifest->sig_scheme, entry.Block0SignatureMagic, false))
		return Failure;

	if (entry.siglen > sizeof(entry.Block0Signature)) {
		LOG_ERR("Block1 Block0 Entry: Invalid signature length, %d", entry.siglen);
		return Failure;
	}

	if (intel_pfr_sig_hash_block0(manifest))
		return Failure;

	if (verify_sig(manifest, entry.Block0Signature, entry.siglen, false))
		return Failure;

	return Success;
}

#define LMS_SCHEME(_name, _pubkey_magic, _sig_magic, _hash_type)		\
	static const STRUCT_SECTION_ITERABLE(intel_pfr_sig_scheme, _name) = {	\
		.name = #_name,							\
		.pubkey_magic = _pubkey_magic,					\
		.sig_magic = _sig_magic,					\
		.sig_block_size = LMS_PFM_SIG_BLOCK_SIZE,			\
		.pit_hash_type = HASH_TYPE_SHA256,				\
		.afm_pfm_offset_adjustment = PFM_SIG_BLOCK_SIZE,		\
		.hash_type = _hash_type,					\
		.root_entry_size = sizeof(KEY_ENTRY_lms),			\
		.csk_entry_size = sizeof(CSKENTRY_lms),				\
		.load_root_key = lms_load_root_key,				\
		.verify_csk = lms_verify_csk,					\
		.verify_block0 = lms_verify_block0,				\
	}

LMS_SCHEME(lms_sha256, PUBLIC_LMS256_TAG, SIGNATURE_LMS256_TAG, HASH_TYPE_SHA256);
LMS_SCHEME(lms_sha384, PUBLIC_LMS384_TAG, SIGNATURE_LMS384_TAG, HASH_TYPE_SHA384);
