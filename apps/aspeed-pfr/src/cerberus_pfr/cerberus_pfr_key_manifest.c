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

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int cerberus_get_root_key_hash(struct pfr_manifest *manifest, uint32_t address, uint32_t hash_type, uint8_t *hash_buf, uint32_t buf_length)
{
	uint32_t read_address = address;
	uint32_t digest_length;
	uint16_t modulus_length;
	uint8_t exponent_length;
	int status = 0;

	if (!hash_buf)
		return Failure;

	// read modulus length
	if (pfr_spi_read(manifest->flash_id, read_address, sizeof(modulus_length), (uint8_t *)&modulus_length)) {
		LOG_ERR("Root Key: Failed to read modulus length");
		return Failure;
	}

	if (modulus_length > RSA_MAX_KEY_LENGTH) {
		LOG_ERR("Root Key: modulus length(%d) exceed max length (%d)", modulus_length, RSA_MAX_KEY_LENGTH);
		return Failure;
	}

	read_address += sizeof(modulus_length) + modulus_length;

	// read exponent length
	if (pfr_spi_read(manifest->flash_id, read_address, sizeof(exponent_length), &exponent_length)) {
		LOG_ERR("Root Key: Failed to read exponent length");
		return Failure;
	}

	if (hash_type == HASH_TYPE_SHA256)
		digest_length = SHA256_DIGEST_LENGTH;
	else if (hash_type == HASH_TYPE_SHA384)
		digest_length = SHA384_DIGEST_LENGTH;
	else if (hash_type == HASH_TYPE_SHA512)
		digest_length = SHA512_DIGEST_LENGTH;
	else {
		LOG_ERR("Root Key: Unsupported hash type(%d)", hash_type);
		return Failure;
	}

	if (digest_length > buf_length) {
		LOG_ERR("Root Key: hash length(%d) exceed buffer length (%d)", digest_length, buf_length);
		return Failure;
	}

	manifest->pfr_hash->start_address = address;
	manifest->pfr_hash->length = sizeof(modulus_length) + modulus_length + sizeof(exponent_length) + exponent_length;
	manifest->pfr_hash->type = hash_type;
	manifest->base->get_hash((struct manifest *)manifest, manifest->hash, hash_buf, digest_length);
	if (status != Success) {
		LOG_ERR("[Root Key]: Get hash failed");
		return Failure;
	}

	return Success;
}

int cerberus_pfr_verify_root_key(struct pfr_manifest *manifest)
{

	uint8_t ufm_sha_data[PROVISIONING_ROOT_KEY_HASH_LENGTH];
	uint8_t hash_buffer[PROVISIONING_ROOT_KEY_HASH_LENGTH];
	uint32_t hash_length = PROVISIONING_ROOT_KEY_HASH_LENGTH;
	uint32_t hash_type = PROVISIONING_ROOT_KEY_HASH_TYPE;
	uint32_t address = CERBERUS_ROOT_KEY_ADDRESS;
	int status = 0;

	manifest->flash_id = ROT_INTERNAL_KEY;
	if (cerberus_get_root_key_hash(manifest, address, hash_type, hash_buffer, sizeof(hash_buffer))) {
		LOG_ERR("Failed to get root key hash.");
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

	LOG_INF("Verify root key success");
	return Success;
}

