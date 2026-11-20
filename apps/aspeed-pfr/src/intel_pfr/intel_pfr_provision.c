/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <zephyr/logging/log.h>
#include <stdint.h>
#include "AspeedStateMachine/common_smc.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_ufm.h"
#include "intel_pfr_definitions.h"
#include "pfr/pfr_util.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_verification.h"
#include "intel_pfr_sig_scheme.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int intel_pfr_check_root_key_hash(const uint8_t *digest, uint32_t length,
				  const uint8_t *key, uint32_t key_length)
{
	uint8_t ufm_sha_data[SHA384_DIGEST_LENGTH] = { 0 };
	int status;

	if (length > sizeof(ufm_sha_data))
		return Failure;

	// Read hash from provisoned UFM 0
	status = ufm_read(PROVISION_UFM, ROOT_KEY_HASH, ufm_sha_data, length);
	if (status != Success) {
		LOG_ERR("Block1 Root Entry: Read hash from UFM failed");
		return status;
	}

	if (memcmp(digest, ufm_sha_data, length)) {
		LOG_ERR("Block1 Root Entry: hash not matched");
		LOG_HEXDUMP_INF(key, key_length, "Public key:");
		LOG_HEXDUMP_INF(digest, length, "Calculated hash:");
		LOG_HEXDUMP_INF(ufm_sha_data, length, "Expected hash:");
		return Failure;
	}

	return Success;
}

// Block1 Root Entry
int verify_root_key_entry(struct pfr_manifest *manifest)
{
	uint32_t addr = intel_pfr_root_entry_addr(manifest);
	struct intel_pfr_key_entry_hdr root;

	if (pfr_spi_read(manifest->image_type, addr, sizeof(root), (uint8_t *)&root)) {
		LOG_ERR("Block1 Root Entry: Flash read data failed");
		return Failure;
	}

	if (root.tag != BLOCK1_ROOTENTRY_TAG) {
		LOG_ERR("Block1 Root Entry: Magic/Tag not matched, %x", root.tag);
		return Failure;
	}

	if (root.pubkey_magic != manifest->sig_scheme->pubkey_magic) {
		LOG_ERR("Block1 Root Entry: curve magic not support, %x", root.pubkey_magic);
		return Failure;
	}

	// Key permission
	if (root.key_permission != INTEL_PFR_ROOT_KEY_ANY) {
		LOG_ERR("Block1 Root Entry: key permission not matched, %x", root.key_permission);
		return Failure;
	}

	// Key Cancellation
	if (root.key_id != INTEL_PFR_ROOT_KEY_ANY) {
		LOG_ERR("Block1 Root Entry: key id not matched, %x", root.key_id);
		return Failure;
	}

	return manifest->sig_scheme->load_root_key(manifest, addr);
}
