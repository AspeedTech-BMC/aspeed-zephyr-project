/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_CERBERUS_PFR)
#include <stddef.h>
#include "pfr/pfr_common.h"

#define DECOMMISSION_CAPSULE             0x200
#define KEY_CANCELLATION_CAPSULE         0x300
#define HASH_STORAGE_LENGTH	256

enum {
	PFR_CPLD_UPDATE_CAPSULE = 0x00,
	PFR_PCH_PFM,
	PFR_PCH_UPDATE_CAPSULE,
	PFR_BMC_PFM,
	PFR_BMC_UPDATE_CAPSULE,
	PFR_PCH_CPU_Seamless_Update_Capsule,
	PFR_AFM,
	PFR_CPLD_UPDATE_CAPSULE_DECOMMISSON = 0x200
};

// Key Cancellation Enum
enum {
	CPLD_CAPSULE_CANCELLATION = 0x100,
	PCH_PFM_CANCELLATION,
	PCH_CAPSULE_CANCELLATION,
	BMC_PFM_CANCELLATION,
	BMC_CAPSULE_CANCELLATION,
	SEAMLESS_CAPSULE_CANCELLATION
};

struct pfr_authentication {
	int (*verify_pfm_signature)(struct pfr_manifest *manifest);
	int (*verify_regions)(struct pfr_manifest *manifest);
};

int get_rsa_public_key(uint8_t flash_id, uint32_t address, struct rsa_public_key *public_key);
int manifest_verify(struct manifest *manifest, struct hash_engine *hash,
		struct signature_verification *verification, uint8_t *hash_out,
		size_t hash_length);
#endif // CONFIG_CERBERUS_PFR
