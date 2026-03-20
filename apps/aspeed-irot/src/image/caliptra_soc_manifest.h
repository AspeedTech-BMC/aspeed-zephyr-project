/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include <image/caliptra_soc_manifest_common.h>

/* Caliptra SOC Manifest Version 2 */
#define CPTRA_MANIFEST_MARKER 0x324D5441 /* "2MTA" */

struct cptra_image_metadata_entry {
	uint32_t image_identifier;
	uint32_t component_id;
	uint32_t classification;
	uint32_t flags;
	
	// Reserved
	uint32_t image_load_address_low;
	// Load Address to DRAM
	uint32_t image_load_address_high;

	// Image Size in bytes
	uint32_t staging_address_low;
	// Flash offset of the image
	uint32_t staging_address_high;

	uint8_t image_hash[48];
} __attribute__((packed));

struct cptra_image_metadata_collection {
	uint32_t count;
	struct cptra_image_metadata_entry entries[];
} __attribute__((packed));

struct cptra_soc_manifest_preamble_v2 {
	uint32_t marker;
	uint32_t size;
	uint32_t version;
	uint32_t svn;
	uint32_t flags;

	struct cptra_ecc_pub_key vendor_ecc_pub_key;
	struct cptra_pqc_pub_key vendor_pqc_pub_key;

	struct cptra_ecc_signature vendor_ecc_signature;
	struct cptra_pqc_signature vendor_pqc_signature;

	struct cptra_ecc_pub_key owner_ecc_pub_key;
	struct cptra_pqc_pub_key owner_pqc_pub_key;

	struct cptra_ecc_signature owner_ecc_signature;
	struct cptra_pqc_signature owner_pqc_signature;
	
	struct cptra_ecc_signature imc_vendor_ecc_signature;
	struct cptra_pqc_signature imc_vendor_pqc_signature;

	struct cptra_ecc_signature imc_owner_ecc_signature;
	struct cptra_pqc_signature imc_owner_pqc_signature;

} __attribute__((packed));

struct cptra_soc_manifest_context {
	struct cptra_soc_manifest_preamble_v2 *preamble;
	struct cptra_image_metadata_collection *imc;
};

extern struct firmware_manifest_handler cptra_soc_manifest_handler;

/* End of Caliptra SOC Manifest Version 2 */
