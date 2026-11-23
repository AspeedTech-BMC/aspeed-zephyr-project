/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include <zephyr/sys/iterable_sections.h>
#include "pfr/pfr_common.h"
#include "intel_pfr_verification.h"

struct intel_pfr_key_entry_hdr {
	uint32_t tag;
	uint32_t pubkey_magic;
	uint32_t key_permission;
	uint32_t key_id;
} __packed;

#define INTEL_PFR_BLOCK1_HDR_SIZE	16
#define INTEL_PFR_ROOT_KEY_ANY		0xFFFFFFFF

struct intel_pfr_sig_scheme {
	const char *name;
	uint32_t pubkey_magic;
	uint32_t sig_magic;
	uint32_t sig_block_size;
	uint32_t hash_type;
	uint32_t pit_hash_type;
	uint32_t afm_pfm_offset_adjustment;
	uint32_t root_entry_size;
	uint32_t csk_entry_size;

	int (*load_root_key)(struct pfr_manifest *manifest, uint32_t addr);
	int (*verify_csk)(struct pfr_manifest *manifest, uint32_t addr);
	int (*verify_block0)(struct pfr_manifest *manifest, uint32_t addr);
};

const struct intel_pfr_sig_scheme *intel_pfr_sig_scheme_find(uint32_t pubkey_magic);
const struct intel_pfr_sig_scheme *intel_pfr_sig_scheme_at(uint32_t image_type, uint32_t addr);
const char *intel_pfr_sig_scheme_name(uint32_t magic, bool signature);
int intel_pfr_check_csk_permission(struct pfr_manifest *manifest, uint32_t key_permission);
int intel_pfr_check_sig_magic(const struct intel_pfr_sig_scheme *scheme, uint32_t magic, bool csk);
int intel_pfr_sig_scheme_select(struct pfr_manifest *manifest);

uint32_t intel_pfr_sig_block_size(const struct pfr_manifest *manifest);
uint32_t intel_pfr_sig_block_size_at(uint32_t image_type, uint32_t addr);
uint32_t intel_pfr_sig_hash_type(const struct pfr_manifest *manifest);
uint32_t intel_pfr_hash_length(uint32_t hash_type);
uint8_t *intel_pfr_block0_pc_hash(PFR_AUTHENTICATION_BLOCK0 *block0, uint32_t hash_type);

uint32_t intel_pfr_root_entry_addr(const struct pfr_manifest *manifest);
uint32_t intel_pfr_csk_entry_addr(const struct pfr_manifest *manifest);
uint32_t intel_pfr_block0_entry_addr(const struct pfr_manifest *manifest);

int intel_pfr_sig_hash(struct pfr_manifest *manifest, const uint8_t *data, size_t len);
int intel_pfr_sig_hash_block0(struct pfr_manifest *manifest);
int intel_pfr_ecdsa_verify(struct pfr_manifest *manifest, const uint8_t *r, const uint8_t *s,
			   bool csk);
