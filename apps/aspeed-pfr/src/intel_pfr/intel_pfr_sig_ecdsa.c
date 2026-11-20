/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <zephyr/logging/log.h>
#include "AspeedStateMachine/common_smc.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_verification.h"
#include "intel_pfr_sig_scheme.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

static uint32_t key_len(const struct pfr_manifest *manifest)
{
	return intel_pfr_hash_length(manifest->sig_scheme->hash_type);
}

static int verify_rs(struct pfr_manifest *manifest, const uint8_t *r, const uint8_t *s, bool csk)
{
	struct pfr_pubkey *pubkey = manifest->verification->pubkey;
	uint32_t len = key_len(manifest);

	memcpy(pubkey->signature_r, r, len);
	memcpy(pubkey->signature_s, s, len);

	if (manifest->verification->base->verify_signature(
			(struct signature_verification *)manifest,
			manifest->pfr_hash->hash_out, len, NULL, 2 * len) != Success) {
		if (csk)
			LOG_ERR("Block1 CSK Entry: Verify signature failed");
		else
			LOG_ERR("Block1 Block0 Entry: Verify signature failed");
		LOG_HEXDUMP_INF(pubkey->x, len, "ECDSA X:");
		LOG_HEXDUMP_INF(pubkey->y, len, "ECDSA Y:");
		LOG_HEXDUMP_INF(pubkey->signature_r, len, "ECDSA R:");
		LOG_HEXDUMP_INF(pubkey->signature_s, len, "ECDSA S:");
		LOG_INF("Hash Info: address = %x, length = %x", manifest->pfr_hash->start_address,
			manifest->pfr_hash->length);
		LOG_HEXDUMP_INF(manifest->pfr_hash->hash_out, len, "Calculated D:");
		return Failure;
	}

	return Success;
}

static int ecdsa_load_root_key(struct pfr_manifest *manifest, uint32_t addr)
{
	uint8_t root_public_key[2 * SHA384_DIGEST_LENGTH];
	uint32_t len = key_len(manifest);
	KEY_ENTRY root;
	uint32_t i;

	if (pfr_spi_read(manifest->image_type, addr, sizeof(root), (uint8_t *)&root)) {
		LOG_ERR("Block1 Root Entry: Flash read data failed");
		return Failure;
	}

	for (i = 0; i < len; i++) {
		root_public_key[i] = root.PubKeyX[len - 1 - i];
		root_public_key[i + len] = root.PubKeyY[len - 1 - i];
	}

	if (intel_pfr_sig_hash(manifest, root_public_key, 2 * len)) {
		LOG_ERR("Block1 Root Entry: Get hash failed");
		return Failure;
	}

	if (intel_pfr_check_root_key_hash(manifest->pfr_hash->hash_out, len, root_public_key, 2 * len))
		return Failure;

	memcpy(manifest->verification->pubkey->x, root.PubKeyX, sizeof(root.PubKeyX));
	memcpy(manifest->verification->pubkey->y, root.PubKeyY, sizeof(root.PubKeyY));

	return Success;
}

static int ecdsa_verify_csk(struct pfr_manifest *manifest, uint32_t addr)
{
	CSKENTRY csk;
	int i;

	if (pfr_spi_read(manifest->image_type, addr, sizeof(csk), (uint8_t *)&csk)) {
		LOG_ERR("Block1 CSK Entry: Flash read data failed");
		return Failure;
	}

	if (intel_pfr_check_sig_magic(manifest->sig_scheme, csk.CskSignatureMagic, true))
		return Failure;

	if (intel_pfr_check_csk_permission(manifest, csk.CskEntryInitial.KeyPermission))
		return Failure;

	for (i = 0; i < BLOCK1_CSK_ENTRY_RESERVED_SIZE; i++) {
		if (csk.CskEntryInitial.Reserved[i] != 0) {
			LOG_ERR("Block1 CSK Entry: reserved data failed");
			return Failure;
		}
	}

	if (intel_pfr_sig_hash(manifest, (uint8_t *)&csk.CskEntryInitial.PubCurveMagic,
			       CSK_ENTRY_PC_SIZE)) {
		LOG_ERR("Block1 CSK Entry: Get hash failed");
		return Failure;
	}

	if (verify_rs(manifest, csk.CskSignatureR, csk.CskSignatureS, true))
		return Failure;

	memcpy(manifest->verification->pubkey->x, csk.CskEntryInitial.PubKeyX, key_len(manifest));
	memcpy(manifest->verification->pubkey->y, csk.CskEntryInitial.PubKeyY, key_len(manifest));

	return Success;
}

static int ecdsa_verify_block0(struct pfr_manifest *manifest, uint32_t addr)
{
	BLOCK0ENTRY entry;

	if (pfr_spi_read(manifest->image_type, addr, sizeof(entry), (uint8_t *)&entry)) {
		LOG_ERR("Block1 Block0 Entry: Flash read data failed");
		return Failure;
	}

	if (intel_pfr_check_sig_magic(manifest->sig_scheme, entry.Block0SignatureMagic, false))
		return Failure;

	if (intel_pfr_sig_hash_block0(manifest))
		return Failure;

	if (verify_rs(manifest, entry.Block0SignatureR, entry.Block0SignatureS, false))
		return Failure;

	return Success;
}

#define ECDSA_SCHEME(_name, _pubkey_magic, _sig_magic, _hash_type)	\
	static const STRUCT_SECTION_ITERABLE(intel_pfr_sig_scheme, _name) = {	\
		.name = #_name,							\
		.pubkey_magic = _pubkey_magic,					\
		.sig_magic = _sig_magic,					\
		.sig_block_size = PFM_SIG_BLOCK_SIZE,				\
		.pit_hash_type = _hash_type,				\
		.afm_pfm_offset_adjustment = PFM_SIG_BLOCK_SIZE,		\
		.hash_type = _hash_type,					\
		.root_entry_size = sizeof(KEY_ENTRY),				\
		.csk_entry_size = sizeof(CSKENTRY),				\
		.load_root_key = ecdsa_load_root_key,				\
		.verify_csk = ecdsa_verify_csk,					\
		.verify_block0 = ecdsa_verify_block0,				\
	}

ECDSA_SCHEME(ecdsa_p256, PUBLIC_SECP256_TAG, SIGNATURE_SECP256_TAG, HASH_TYPE_SHA256);
ECDSA_SCHEME(ecdsa_p384, PUBLIC_SECP384_TAG, SIGNATURE_SECP384_TAG, HASH_TYPE_SHA384);
