/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <stdint.h>
#include "crypto/rsa.h"
#include "pfr/pfr_common.h"

#define KEY_MANIFEST_SIZE       2048
#define KEY_MANIFEST_0_ADDRESS  0
#define MAX_KEY_MANIFEST_ID (CONFIG_KEY_MANIFEST_MAX_COUNT - 1)
#define MAX_KEY_ID 7

struct PFR_KEY_MANIFEST {
	uint32_t magic_number;
	uint8_t hash_type;
	uint8_t key_count;
	struct key_list {
		uint8_t key_hash[64];
	} key_list[8];
};

int key_manifest_get_root_key(struct rsa_public_key *public_key, uint32_t keym_address);
int cerberus_pfr_get_public_key_hash(struct pfr_manifest *manifest, uint32_t address, uint32_t hash_type, uint8_t *hash_buf, uint32_t buf_length);
int cerberus_pfr_verify_root_key(struct pfr_manifest *manifest, struct rsa_public_key *public_key);
int cerberus_pfr_verify_key_manifest(struct pfr_manifest *manifest, uint8_t keym_id);
int cerberus_pfr_verify_all_key_manifests(struct pfr_manifest *manifest);
int cerberus_pfr_get_key_manifest(struct pfr_manifest *manifest, uint8_t keym_id, struct PFR_KEY_MANIFEST *pfr_key_manifest);
int cerberus_pfr_verify_csk_key(struct pfr_manifest *manifest, struct rsa_public_key *public_key, uint8_t key_manifest_id, uint8_t key_id);
int cerberus_pfr_find_key_manifest_id(struct pfr_manifest *manifest, struct rsa_public_key *public_key, uint8_t key_id, uint8_t *get_keym_id);

