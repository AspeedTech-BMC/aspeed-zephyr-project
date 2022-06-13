/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <stdint.h>
#include "state_machine/common_smc.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_ufm.h"
#include "intel_pfr_definitions.h"
#include "pfr/pfr_util.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_verification.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);


// Verify Root Key hash
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
	else
		return Failure;

	// Changing Endianess
	for (i = 0; i < digest_length; i++) {
		root_public_key[i] = pubkey_x[digest_length - 1 - i];
		root_public_key[i + digest_length] = pubkey_y[digest_length - 1 - i];
	}

	status = get_buffer_hash(manifest, root_public_key, digest_length * 2, sha_buffer);
	if (status != Success)
		return Failure;

	// Read hash from provisoned UFM 0
	status = ufm_read(PROVISION_UFM, ROOT_KEY_HASH, ufm_sha_data, digest_length);
	if (status != Success)
		return status;

	status = compare_buffer(sha_buffer, ufm_sha_data, digest_length);
	if (status != Success) {
		LOG_HEXDUMP_INF(root_public_key, digest_length*2, "Root public key:");
		LOG_HEXDUMP_INF(sha_buffer, digest_length, "Root key hash:");
		LOG_HEXDUMP_INF(sha_buffer, digest_length, "UFM root key hash:");
		LOG_ERR("Root key hash not matched");
		return Failure;
	}

	return Success;
}

// Root Entry Key
int verify_root_key_entry(struct pfr_manifest *manifest, PFR_AUTHENTICATION_BLOCK1 *block1_buffer)
{
	int root_key_permission = 0xFFFFFFFF;    // -1;
	int status;

	if (block1_buffer->RootEntry.Tag != BLOCK1_ROOTENTRY_TAG) {
		LOG_ERR("Root Magic/Tag not matched");
		return Failure;
	}

	// Update CSK curve type to validate Block 0 entry
	if (block1_buffer->RootEntry.PubCurveMagic == PUBLIC_SECP256_TAG)
		manifest->hash_curve = secp256r1;
	else if (block1_buffer->RootEntry.PubCurveMagic == PUBLIC_SECP384_TAG)
		manifest->hash_curve = secp384r1;
	else {
		LOG_ERR("Root public curve magic not support %x", block1_buffer->RootEntry.PubCurveMagic);
		return Failure;
	}

	// Key permission
	if (block1_buffer->RootEntry.KeyPermission != root_key_permission) {
		LOG_ERR("Root key permission not matched");
		return Failure;
	}

	// Key Cancellation
	if (block1_buffer->RootEntry.KeyId != root_key_permission) {
		LOG_ERR("Root key id not matched");
		return Failure;
	}

	status = verify_root_key_hash(manifest, block1_buffer->RootEntry.PubKeyX, block1_buffer->RootEntry.PubKeyY);
	if (status != Success) {
		LOG_ERR("Verify root key hash not matched");
		return Failure;
	}

	return Success;
}
