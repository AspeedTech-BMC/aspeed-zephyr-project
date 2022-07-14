/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <stdint.h>
#include "AspeedStateMachine/common_smc.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_ufm.h"
#include "intel_pfr_definitions.h"
#include "pfr/pfr_util.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_verification.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);


int verify_root_key_hash(struct pfr_manifest *manifest, uint8_t *pubkey_x, uint8_t *pubkey_y)
{
	uint8_t root_public_key[SHA384_DIGEST_LENGTH * 2] = { 0 };
	uint8_t ufm_sha_data[SHA384_DIGEST_LENGTH] = { 0 };
	uint8_t sha_buffer[SHA384_DIGEST_LENGTH] = { 0 };
	uint8_t digest_length = 0;
	uint8_t i = 0;
	int status;

	if (manifest->hash_curve == secp256r1)
		digest_length = SHA256_DIGEST_LENGTH;
	else if (manifest->hash_curve == secp384r1)
		digest_length = SHA384_DIGEST_LENGTH;
	else {
		LOG_ERR("Block1 Root Entry: Unsupported hash curve, %x", manifest->hash_curve);
		return Failure;
	}

	// Changing little endianess
	for (i = 0; i < digest_length; i++) {
		root_public_key[i] = pubkey_x[digest_length - 1 - i];
		root_public_key[i + digest_length] = pubkey_y[digest_length - 1 - i];
	}

	status = get_buffer_hash(manifest, root_public_key, digest_length * 2, sha_buffer);
	if (status != Success) {
		LOG_ERR("Block1 Root Entry: Get buffer hash failed");
		return Failure;
	}

	// Read hash from provisoned UFM 0
	status = ufm_read(PROVISION_UFM, ROOT_KEY_HASH, ufm_sha_data, digest_length);
	if (status != Success) {
		LOG_ERR("Block1 Root Entry: Read hash from UFM failed");
		return status;
	}

	status = compare_buffer(sha_buffer, ufm_sha_data, digest_length);
	if (status != Success) {
		LOG_ERR("Block1 Root Entry: hash not matched");
		LOG_HEXDUMP_INF(root_public_key, digest_length*2, "Public key:");
		LOG_HEXDUMP_INF(sha_buffer, digest_length, "Calculated hash:");
		LOG_HEXDUMP_INF(ufm_sha_data, digest_length, "Expected hash:");
		return Failure;
	}

	return Success;
}

// Block1 Root Entry
int verify_root_key_entry(struct pfr_manifest *manifest, PFR_AUTHENTICATION_BLOCK1 *block1_buffer)
{
	uint32_t root_key_permission = 0xFFFFFFFF; // -1;
	int status;

	if (block1_buffer->RootEntry.Tag != BLOCK1_ROOTENTRY_TAG) {
		LOG_ERR("Block1 Root Entry: Magic/Tag not matched, %x", block1_buffer->RootEntry.Tag);
		return Failure;
	}

	// Update root key entry curve type to validate csk/b0 entry
	if (block1_buffer->RootEntry.PubCurveMagic == PUBLIC_SECP256_TAG)
		manifest->hash_curve = secp256r1;
	else if (block1_buffer->RootEntry.PubCurveMagic == PUBLIC_SECP384_TAG)
		manifest->hash_curve = secp384r1;
	else {
		LOG_ERR("Block1 Root Entry: curve magic not support, %x", block1_buffer->RootEntry.PubCurveMagic);
		return Failure;
	}

	// Key permission
	if (block1_buffer->RootEntry.KeyPermission != root_key_permission) {
		LOG_ERR("Block1 Root Entry: key permission not matched, %x", block1_buffer->RootEntry.KeyPermission);
		return Failure;
	}

	// Key Cancellation
	if (block1_buffer->RootEntry.KeyId != root_key_permission) {
		LOG_ERR("Block1 Root Entry: key id not matched, %x", block1_buffer->RootEntry.KeyId);
		return Failure;
	}

	status = verify_root_key_hash(manifest, block1_buffer->RootEntry.PubKeyX, block1_buffer->RootEntry.PubKeyY);
	if (status != Success)
		return Failure;

	return Success;
}
