/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include "pfr/pfr_common.h"

#define MAX_CANCEL_KEY 8

#pragma pack(1)
struct PFR_KEY_CANCELLATION_MANIFEST {
	uint32_t magic_number;
	uint16_t key_policy;
	uint8_t hash_type;
	uint8_t key_count;
	struct key_cancel_list {
		uint8_t key_id;
		uint8_t key_hash[64];
	} key_cancel_list[8];
};
#pragma pack()

int get_cancellation_policy_offset(uint32_t pc_type);
int verify_csk_key_id(struct pfr_manifest *manifest, uint8_t key_manifest_id, uint8_t key_id);
int cancel_csk_key_id(struct pfr_manifest *manifest, uint8_t key_manifest_id, uint8_t key_id);
int cerberus_pfr_cancel_csk_keys(struct pfr_manifest *manifest);

