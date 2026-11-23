/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/crypto/mldsa.h>
#include "AspeedStateMachine/common_smc.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_verification.h"
#include "intel_pfr_sig_scheme.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

BUILD_ASSERT(sizeof(KEY_ENTRY_HYBRID) == 2704);
BUILD_ASSERT(sizeof(CSKENTRY_HYBRID) == 7432);
BUILD_ASSERT(sizeof(BLOCK0ENTRY_HYBRID) == 4732);
BUILD_ASSERT(MLDSA87_PUBKEY_SIZE == MLDSA87_PUB_KEY_LEN);
BUILD_ASSERT(MLDSA87_SIGNATURE_SIZE == MLDSA87_SIG_LEN);

static const struct device *const mldsa_dev = DEVICE_DT_GET_ONE(aspeed_cptra_mci_mldsa);

static struct mldsa_pub_key mldsa_key;
static struct mldsa_pkt mldsa_pkt;
static union {
	KEY_ENTRY_HYBRID root;
	CSKENTRY_HYBRID csk;
	BLOCK0ENTRY_HYBRID b0;
} entry;

static int mldsa_verify_msg(const uint8_t *msg, size_t len, const uint8_t *sig)
{
	struct mldsa_ctx ctx = { 0 };
	int ret;

	if (!device_is_ready(mldsa_dev)) {
		LOG_ERR("ML-DSA device not ready");
		return Failure;
	}

	memcpy(mldsa_pkt.sig, sig, sizeof(mldsa_pkt.sig));
	mldsa_pkt.m = (uint8_t *)msg;
	mldsa_pkt.m_len = len;

	ret = mldsa_begin_session(mldsa_dev, &ctx, &mldsa_key);
	if (ret) {
		LOG_ERR("ML-DSA begin session failed: %d", ret);
		return Failure;
	}

	ret = mldsa_verify(&ctx, &mldsa_pkt);
	mldsa_free_session(mldsa_dev, &ctx);

	return ret ? Failure : Success;
}

static void load_key(struct pfr_manifest *manifest, const KEY_ENTRY_HYBRID *key)
{
	memcpy(manifest->verification->pubkey->x, key->PubKeyX, sizeof(key->PubKeyX));
	memcpy(manifest->verification->pubkey->y, key->PubKeyY, sizeof(key->PubKeyY));
	memcpy(mldsa_key.key, key->MldsaPubKey, sizeof(mldsa_key.key));
}

static int verify_both(struct pfr_manifest *manifest, const uint8_t *msg, size_t len,
		       const uint8_t *r, const uint8_t *s, const uint8_t *mldsa_sig, bool csk)
{
	if (intel_pfr_ecdsa_verify(manifest, r, s, csk))
		return Failure;

	if (mldsa_verify_msg(msg, len, mldsa_sig)) {
		LOG_ERR("ML-DSA-87 signature verify failed");
		if (csk)
			LOG_ERR("Block1 CSK Entry: Verify signature failed");
		else
			LOG_ERR("Block1 Block0 Entry: Verify signature failed");
		return Failure;
	}

	return Success;
}

static int hybrid_load_root_key(struct pfr_manifest *manifest, uint32_t addr)
{
	KEY_ENTRY_HYBRID *root = &entry.root;
	size_t key_len = sizeof(*root) - offsetof(KEY_ENTRY_HYBRID, PubKeyX);

	if (pfr_spi_read(manifest->image_type, addr, sizeof(*root), (uint8_t *)root)) {
		LOG_ERR("Block1 Root Entry: Flash read data failed");
		return Failure;
	}

	if (intel_pfr_sig_hash(manifest, root->PubKeyX, key_len)) {
		LOG_ERR("Block1 Root Entry: Get hash failed");
		return Failure;
	}

	if (intel_pfr_check_root_key_hash(manifest->pfr_hash->hash_out, SHA384_DIGEST_LENGTH,
					  root->PubKeyX, key_len))
		return Failure;

	load_key(manifest, root);

	return Success;
}

static int hybrid_verify_csk(struct pfr_manifest *manifest, uint32_t addr)
{
	CSKENTRY_HYBRID *csk = &entry.csk;
	const uint8_t *msg = (const uint8_t *)&csk->CskEntryInitial.PubCurveMagic;
	size_t len = sizeof(csk->CskEntryInitial) - offsetof(KEY_ENTRY_HYBRID, PubCurveMagic);

	if (pfr_spi_read(manifest->image_type, addr, sizeof(*csk), (uint8_t *)csk)) {
		LOG_ERR("Block1 CSK Entry: Flash read data failed");
		return Failure;
	}

	if (intel_pfr_check_sig_magic(manifest->sig_scheme, csk->CskSignatureMagic, true))
		return Failure;

	if (intel_pfr_check_csk_permission(manifest, csk->CskEntryInitial.KeyPermission))
		return Failure;

	manifest->pfr_hash->start_address = addr + offsetof(KEY_ENTRY_HYBRID, PubCurveMagic);
	manifest->pfr_hash->length = len;
	if (intel_pfr_sig_hash(manifest, msg, len)) {
		LOG_ERR("Block1 CSK Entry: Get hash failed");
		return Failure;
	}

	if (verify_both(manifest, msg, len, csk->CskSignatureR, csk->CskSignatureS,
			csk->CskMldsaSignature, true))
		return Failure;

	load_key(manifest, &csk->CskEntryInitial);

	return Success;
}

static int hybrid_verify_block0(struct pfr_manifest *manifest, uint32_t addr)
{
	BLOCK0ENTRY_HYBRID *b0e = &entry.b0;
	uint8_t block0[sizeof(PFR_AUTHENTICATION_BLOCK0)];

	if (pfr_spi_read(manifest->image_type, addr, sizeof(*b0e), (uint8_t *)b0e) ||
	    pfr_spi_read(manifest->image_type, manifest->address, sizeof(block0), block0)) {
		LOG_ERR("Block1 Block0 Entry: Flash read data failed");
		return Failure;
	}

	if (intel_pfr_check_sig_magic(manifest->sig_scheme, b0e->Block0SignatureMagic, false))
		return Failure;

	manifest->pfr_hash->start_address = manifest->address;
	manifest->pfr_hash->length = sizeof(block0);
	if (intel_pfr_sig_hash(manifest, block0, sizeof(block0))) {
		LOG_ERR("Block1 Block0 Entry: Get hash failed");
		return Failure;
	}

	if (verify_both(manifest, block0, sizeof(block0), b0e->Block0SignatureR,
			b0e->Block0SignatureS, b0e->Block0MldsaSignature, false))
		return Failure;

	return Success;
}

static const STRUCT_SECTION_ITERABLE(intel_pfr_sig_scheme, p384_mldsa87) = {
	.name = "p384_mldsa87",
	.pubkey_magic = PUBLIC_P384_MLDSA87_TAG,
	.sig_magic = SIGNATURE_P384_MLDSA87_TAG,
	.sig_block_size = HYBRID_PFM_SIG_BLOCK_SIZE,
	.hash_type = HASH_TYPE_SHA384,
	.pit_hash_type = HASH_TYPE_SHA384,
	.afm_pfm_offset_adjustment = HYBRID_PFM_SIG_BLOCK_SIZE,
	.root_entry_size = sizeof(KEY_ENTRY_HYBRID),
	.csk_entry_size = sizeof(CSKENTRY_HYBRID),
	.load_root_key = hybrid_load_root_key,
	.verify_csk = hybrid_verify_csk,
	.verify_block0 = hybrid_verify_block0,
};
