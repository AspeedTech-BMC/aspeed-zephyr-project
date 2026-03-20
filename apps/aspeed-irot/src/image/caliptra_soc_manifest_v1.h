/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <stdint.h>
#include <image/firmware_manifest.h>
#include <image/caliptra_soc_manifest_common.h>

#define CPTRA_FLASH_HEADER_MAGIC 0x48534c46 /* FLSH */ 
#define CPTRA_SOC_MANIFEST_V1_MAGIC 0x41544d4e /* "ATMN" */
struct cptra_image_info_v1 {
	/* 
	 * 0x00000000 - Caliptra FMC+RT
	 * 0x00000001 - SoC Manifest
	 * 0x00000002 - MCU Runtime
	 * 0x00001001 - 
	 */
	uint32_t identifier;

	uint32_t image_offset;
	uint32_t image_size;
};

struct cptra_flash_header_v1 {
	uint32_t magic;
	uint16_t version;
	uint16_t image_count;
	uint32_t header_checksum;
	uint32_t payload_checksum;
};

struct cptra_image_metadata_entry_v1 {
	uint32_t firmware_id;
	uint32_t flags;
	uint8_t digest[48];
} __attribute__((packed));

struct cptra_image_metadata_collection_v1 {
	uint32_t count;
	struct cptra_image_metadata_entry_v1 entries[AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT];
} __attribute__((packed));

struct cptra_soc_manifest_preamble_v1 {
	uint32_t marker;
	uint32_t size;
	uint32_t version;
	
	/* ASPEED flavor */
	uint32_t svn;
	/* ASPEED flavor */

	uint32_t flags;

	struct cptra_ecc_pub_key vendor_ecc_pub_key;
	struct cptra_lms_pub_key vendor_lms_pub_key;

	struct cptra_ecc_signature vendor_ecc_signature;
	struct cptra_lms_signature vendor_lms_signature;

	struct cptra_ecc_pub_key owner_ecc_pub_key;
	struct cptra_lms_pub_key owner_lms_pub_key;

	struct cptra_ecc_signature owner_ecc_signature;
	struct cptra_lms_signature owner_lms_signature;

	/* ASPEED flavor start */
	struct cptra_ecc_signature owner_manifest2_ecc_signature;
	struct cptra_lms_signature owner_manifest2_lms_signature;
	/* ASPEED flavor end */

	struct cptra_ecc_signature vendor_imc_ecc_signature;
	struct cptra_lms_signature vendor_imc_lms_signature;
	
	struct cptra_ecc_signature owner_imc_ecc_signature;
	struct cptra_lms_signature owner_imc_lms_signature;
} __attribute__((packed));

extern struct firmware_manifest_handler cptra_soc_manifest_v1_handler;

int cptra_validate_bundle_v1(const uint8_t *bundle, size_t bundle_size);
