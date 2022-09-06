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
#define HASH_STORAGE_LENGTH	         256
#define PLATFORM_ID_HEADER_LENGTH                       0x04
#define CERBERUS_FLASH_DEVICE_OFFSET_LENGTH             0x04
#define CERRBERUS_FW_VERSION_ADDR_LENGTH                0x04


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
enum CERBERUS_PFM_MANIFEST_HEADER {
	PFM_HEADER_TOTAL_LENGTH                 = 0x00,
	PFM_HEADER_MAGIC_ID                     = 0x02,
	PFM_HEADER_MANIFEST_ID                  = 0x04,
	PFM_HEADER_SIG_LENGTH                   = 0x08,
	PFM_HEADER_SIG_TYPE                     = 0x0A,
	PFM_HEADER_RESERVED,
	PFM_TOC_ENTRY_COUNT,
	PFM_TOC_COUNT,
	PFM_TOC_HASH_TYPE,
	PFM_TOC_RESERVED,
	TOC_ELEMENT_LIST_OFFSET,
	TOC_ELEMENT_HASH_LIST_OFFSET            = 0x30,
	TOC_TABLE_HASH_OFFSET                   = 0xB0,
	CERBERUS_PLATFORM_HEADER_OFFSET         = 0xD0
};

struct CERBERUS_PFM_RW_REGION {
	uint8_t flags;
	uint8_t reserved[3];
	uint32_t start_address;
	uint32_t end_address;
};

struct CERBERUS_SIGN_IMAGE_HEADER {
	uint8_t hash_type;
	uint8_t region_count;
	uint8_t flag;
	uint8_t reserved;
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
int cerberus_pfr_verify_image(struct pfr_manifest *pfr_manifest);
int cerberus_verify_regions(struct manifest *manifest);
void init_stage_and_recovery_offset(struct pfr_manifest *pfr_manifest);
#endif // CONFIG_CERBERUS_PFR
