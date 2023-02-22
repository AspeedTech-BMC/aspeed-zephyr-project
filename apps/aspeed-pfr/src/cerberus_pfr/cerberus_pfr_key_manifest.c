/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>
#include <logging/log.h>
#include <stdint.h>
#include "flash/flash_aspeed.h"
#include "AspeedStateMachine/common_smc.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "pfr/pfr_ufm.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_key_manifest.h"
#include "cerberus_pfr_recovery.h"
#include "cerberus_pfr_verification.h"
#include "crypto/rsa.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int cerberus_get_public_key_hash(struct pfr_manifest *manifest, uint32_t address, uint32_t hash_type, uint8_t *hash_buf, uint32_t buf_length)
{
	uint32_t digest_length;
	int status;

	if (!hash_buf)
		return Failure;

	if (hash_type == HASH_TYPE_SHA256)
		digest_length = SHA256_DIGEST_LENGTH;
	else if (hash_type == HASH_TYPE_SHA384)
		digest_length = SHA384_DIGEST_LENGTH;
	else {
		LOG_ERR("Root Key: Unsupported hash type(%d)", hash_type);
		return Failure;
	}

	if (digest_length > buf_length) {
		LOG_ERR("Root Key: hash length(%d) exceed buffer length (%d)", digest_length, buf_length);
		return Failure;
	}

	manifest->pfr_hash->start_address = address;
	manifest->pfr_hash->length = sizeof(struct rsa_public_key);
	manifest->pfr_hash->type = hash_type;
	status = manifest->base->get_hash((struct manifest *)manifest, manifest->hash, hash_buf, digest_length);
	if (status != Success) {
		LOG_ERR("Get hash failed");
		return Failure;
	}

	return Success;
}

/*
 * The root public key is placed in each key manifest.
 * The contentes of root public key from all key manifests should be identical,
 * because it has only one root public key.
 */
int key_manifest_get_root_key(struct rsa_public_key *public_key, uint32_t address)
{
	struct recovery_header image_header;
	uint32_t read_address = 0;
	int status = Success;

	pfr_spi_read(ROT_INTERNAL_KEY, address, sizeof(image_header), (uint8_t *)&image_header);
	status = verify_recovery_header_magic_number(image_header);
	if (status != Success) {
		LOG_HEXDUMP_ERR(&image_header, sizeof(image_header), "image_header:");
		LOG_ERR("Image Header Magic Number is not Matched.");
		return Failure;
	}

	read_address = address + image_header.image_length;
	pfr_spi_read(ROT_INTERNAL_KEY, read_address, sizeof(struct rsa_public_key), (uint8_t *)public_key);
	if (public_key->mod_length != image_header.sign_length) {
		LOG_ERR("root key length(%d) and signature length (%d) mismatch", public_key->mod_length, image_header.sign_length);
		return Failure;
	}

	return status;
}

int cerberus_verify_root_key(struct pfr_manifest *manifest, struct rsa_public_key *public_key)
{
	uint8_t ufm_sha_data[PROVISIONING_ROOT_KEY_HASH_LENGTH];
	uint8_t hash_buffer[PROVISIONING_ROOT_KEY_HASH_LENGTH];
	uint32_t hash_length = PROVISIONING_ROOT_KEY_HASH_LENGTH;
	int status = 0;

	if (!public_key)
		return Failure;

	if (PROVISIONING_ROOT_KEY_HASH_TYPE == HASH_TYPE_SHA256) {
		manifest->hash->start_sha256(manifest->hash);
		manifest->hash->calculate_sha256(manifest->hash, (uint8_t *)public_key, sizeof(struct rsa_public_key), hash_buffer, SHA256_HASH_LENGTH);
	} else if (PROVISIONING_ROOT_KEY_HASH_TYPE == HASH_TYPE_SHA384) {
		manifest->hash->start_sha384(manifest->hash);
		manifest->hash->calculate_sha384(manifest->hash, (uint8_t *)public_key, sizeof(struct rsa_public_key), hash_buffer, SHA384_HASH_LENGTH);
	} else {
		LOG_ERR("Unsupported hash type(%d)", PROVISIONING_ROOT_KEY_HASH_TYPE);
		return Failure;
	}

	// Read hash from provisoned UFM 0
	status = ufm_read(PROVISION_UFM, ROOT_KEY_HASH, ufm_sha_data, hash_length);
	if (status != Success) {
		LOG_ERR("Failed to read root key hash from UFM.");
		return status;
	}

	if (memcmp(hash_buffer, ufm_sha_data, hash_length)) {
		LOG_ERR("Verify root key failed.");
		LOG_HEXDUMP_INF(hash_buffer, hash_length, "Calculated hash:");
		LOG_HEXDUMP_INF(ufm_sha_data, hash_length, "Expected hash:");
		return Failure;
	}

	return Success;
}
