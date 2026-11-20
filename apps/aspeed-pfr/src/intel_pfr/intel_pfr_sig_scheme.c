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
#include "intel_pfr_verification.h"
#include "intel_pfr_sig_scheme.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

static const struct intel_pfr_sig_scheme *scheme_by_magic(uint32_t magic, bool signature)
{
	STRUCT_SECTION_FOREACH(intel_pfr_sig_scheme, scheme) {
		if (magic == (signature ? scheme->sig_magic : scheme->pubkey_magic))
			return scheme;
	}

	return NULL;
}

const struct intel_pfr_sig_scheme *intel_pfr_sig_scheme_find(uint32_t pubkey_magic)
{
	return scheme_by_magic(pubkey_magic, false);
}

const char *intel_pfr_sig_scheme_name(uint32_t magic, bool signature)
{
	const struct intel_pfr_sig_scheme *scheme = scheme_by_magic(magic, signature);

	return scheme ? scheme->name : "unknown";
}

const struct intel_pfr_sig_scheme *intel_pfr_sig_scheme_at(uint32_t image_type, uint32_t addr)
{
	struct intel_pfr_key_entry_hdr root;

	if (pfr_spi_read(image_type, addr + sizeof(PFR_AUTHENTICATION_BLOCK0) +
			 INTEL_PFR_BLOCK1_HDR_SIZE, sizeof(root), (uint8_t *)&root))
		return NULL;

	return intel_pfr_sig_scheme_find(root.pubkey_magic);
}

int intel_pfr_check_sig_magic(const struct intel_pfr_sig_scheme *scheme, uint32_t magic, bool csk)
{
	const struct intel_pfr_sig_scheme *actual;

	if (magic == scheme->sig_magic)
		return Success;

	actual = scheme_by_magic(magic, true);
	if (csk) {
		if (actual)
			LOG_ERR("Block1 CSK Entry: CSK key and signature scheme not matched, key = %s (%x), sig = %s (%x)",
				scheme->name, scheme->pubkey_magic, actual->name, magic);
		else
			LOG_ERR("Block1 CSK Entry: Unsupported signature magic, %x", magic);
	} else {
		if (actual)
			LOG_ERR("Block1 Block0 Entry: Key and Block0 signature scheme not matched, key = %s (%x), sig = %s (%x)",
				scheme->name, scheme->pubkey_magic, actual->name, magic);
		else
			LOG_ERR("Block1 Block0 Entry: Unsupported signature magic, %x", magic);
	}
	return Failure;
}

int intel_pfr_sig_scheme_select(struct pfr_manifest *manifest)
{
	const struct intel_pfr_sig_scheme *scheme;
	struct {
		uint32_t tag;
		uint8_t reserved[INTEL_PFR_BLOCK1_HDR_SIZE - sizeof(uint32_t)];
		struct intel_pfr_key_entry_hdr root;
	} block1;

	if (pfr_spi_read(manifest->image_type, manifest->address + sizeof(PFR_AUTHENTICATION_BLOCK0),
			 sizeof(block1), (uint8_t *)&block1)) {
		LOG_ERR("Block1: Flash read data failed");
		return Failure;
	}

	scheme = intel_pfr_sig_scheme_find(block1.root.pubkey_magic);
	if (!scheme) {
		if (block1.root.pubkey_magic == PUBLIC_LMS384_TAG ||
		    block1.root.pubkey_magic == PUBLIC_LMS256_TAG) {
			LOG_ERR("Block1 Root Entry: unsupported public key");
		} else if (block1.tag != BLOCK1TAG) {
			LOG_ERR("Block1: Tag Not Found, %x", block1.tag);
		} else if (block1.root.tag != BLOCK1_ROOTENTRY_TAG) {
			LOG_ERR("Block1 Root Entry: Magic/Tag not matched, %x", block1.root.tag);
			LOG_ERR("Block1 Root Entry: Validation failed");
		} else {
			LOG_ERR("Block1 Root Entry: curve magic not support, %x", block1.root.pubkey_magic);
			LOG_ERR("Block1 Root Entry: Validation failed");
		}
		return Failure;
	}

	manifest->sig_scheme = scheme;

	return Success;
}

uint32_t intel_pfr_sig_block_size(const struct pfr_manifest *manifest)
{
	return manifest->sig_scheme ? manifest->sig_scheme->sig_block_size : PFM_SIG_BLOCK_SIZE;
}

uint32_t intel_pfr_sig_block_size_at(uint32_t image_type, uint32_t addr)
{
	const struct intel_pfr_sig_scheme *scheme = intel_pfr_sig_scheme_at(image_type, addr);

	return scheme ? scheme->sig_block_size : PFM_SIG_BLOCK_SIZE;
}

uint32_t intel_pfr_sig_hash_type(const struct pfr_manifest *manifest)
{
	return manifest->sig_scheme ? manifest->sig_scheme->hash_type : HASH_TYPE_SHA256;
}

uint32_t intel_pfr_hash_length(uint32_t hash_type)
{
	return (hash_type == HASH_TYPE_SHA384) ? SHA384_DIGEST_LENGTH : SHA256_DIGEST_LENGTH;
}

uint8_t *intel_pfr_block0_pc_hash(PFR_AUTHENTICATION_BLOCK0 *block0, uint32_t hash_type)
{
	return (hash_type == HASH_TYPE_SHA384) ? block0->Sha384Pc : block0->Sha256Pc;
}

uint32_t intel_pfr_root_entry_addr(const struct pfr_manifest *manifest)
{
	return manifest->address + sizeof(PFR_AUTHENTICATION_BLOCK0) + INTEL_PFR_BLOCK1_HDR_SIZE;
}

uint32_t intel_pfr_csk_entry_addr(const struct pfr_manifest *manifest)
{
	return intel_pfr_root_entry_addr(manifest) + manifest->sig_scheme->root_entry_size;
}

uint32_t intel_pfr_block0_entry_addr(const struct pfr_manifest *manifest)
{
	uint32_t addr = intel_pfr_csk_entry_addr(manifest);

	if (!manifest->kc_flag)
		addr += manifest->sig_scheme->csk_entry_size;

	return addr;
}

int intel_pfr_sig_hash(struct pfr_manifest *manifest, const uint8_t *data, size_t len)
{
	struct hash_engine *hash = manifest->hash;
	uint8_t *out = manifest->pfr_hash->hash_out;

	manifest->pfr_hash->type = manifest->sig_scheme->hash_type;
	if (manifest->sig_scheme->hash_type == HASH_TYPE_SHA384) {
		hash->start_sha384(hash);
		return hash->calculate_sha384(hash, data, len, out, SHA384_HASH_LENGTH);
	}

	hash->start_sha256(hash);
	return hash->calculate_sha256(hash, data, len, out, SHA256_HASH_LENGTH);
}

int intel_pfr_sig_hash_block0(struct pfr_manifest *manifest)
{
	uint32_t hash_type = manifest->sig_scheme->hash_type;

	manifest->flash->state->device_id[0] = manifest->image_type;
	manifest->pfr_hash->type = hash_type;
	manifest->pfr_hash->start_address = manifest->address;
	manifest->pfr_hash->length = sizeof(PFR_AUTHENTICATION_BLOCK0);

	if (manifest->base->get_hash((struct manifest *)manifest, manifest->hash,
				     manifest->pfr_hash->hash_out,
				     intel_pfr_hash_length(hash_type))) {
		LOG_ERR("Block1 Block0 Entry: Get hash failed");
		return Failure;
	}

	return Success;
}
