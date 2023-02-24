/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <stdint.h>
#include "crypto/rsa.h"

#define KEY_MANIFEST_SIZE       2048
#define KEY_MANIFEST_0_ADDRESS  0

int key_manifest_get_root_key(struct rsa_public_key *public_key, uint32_t keym_address);
int cerberus_pfr_get_public_key_hash(struct pfr_manifest *manifest, uint32_t address, uint32_t hash_type, uint8_t *hash_buf, uint32_t buf_length);
int cerberus_pfr_verify_root_key(struct pfr_manifest *manifest, struct rsa_public_key *public_key);
int cerberus_pfr_verify_key_manifest_id(struct pfr_manifest *manifest, uint32_t keym_id);
int cerberus_pfr_verify_key_manifests(struct pfr_manifest *manifest);

