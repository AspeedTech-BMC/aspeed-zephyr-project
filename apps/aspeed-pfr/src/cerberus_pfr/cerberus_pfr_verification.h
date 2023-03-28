/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stddef.h>
#include "pfr/pfr_common.h"
#include "cerberus_pfr_recovery.h"

enum {
	PFR_CPLD_UPDATE_CAPSULE = 0x00,
	PFR_PCH_PFM,
	PFR_PCH_UPDATE_CAPSULE,
	PFR_BMC_PFM,
	PFR_BMC_UPDATE_CAPSULE,
};

// Key Cancellation Enum
enum {
	CPLD_CAPSULE_CANCELLATION = 0x100,
	PCH_PFM_CANCELLATION,
	PCH_CAPSULE_CANCELLATION,
	BMC_PFM_CANCELLATION,
	BMC_CAPSULE_CANCELLATION,
};

struct pfr_authentication {
	int (*verify_pfm_signature)(struct pfr_manifest *manifest);
	int (*verify_regions)(struct pfr_manifest *manifest);
};

int manifest_verify(struct manifest *manifest, struct hash_engine *hash,
		struct signature_verification *verification, uint8_t *hash_out,
		size_t hash_length);
int cerberus_pfr_verify_image(struct pfr_manifest *pfr_manifest);
int cerberus_verify_regions(struct manifest *manifest);
void init_stage_and_recovery_offset(struct pfr_manifest *pfr_manifest);
int verify_recovery_header_magic_number(struct recovery_header rec_head);

