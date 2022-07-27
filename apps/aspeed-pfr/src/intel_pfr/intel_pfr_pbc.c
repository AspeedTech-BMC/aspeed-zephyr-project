/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <stdint.h>
#include <posix/time.h>
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "flash/flash_wrapper.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_pfm_manifest.h"
#include "intel_pfr_verification.h"
#include "common/common.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#if PF_UPDATE_DEBUG
#define DEBUG_PRINTF LOG_INF
#else
#define DEBUG_PRINTF(...)
#endif

typedef struct {
	uint32_t tag;
	uint32_t version;
	uint32_t page_size;
	uint32_t pattern_size;
	uint32_t pattern;
	uint32_t bitmap_nbit;
	uint32_t payload_len;
	uint32_t _reserved[25];
} PBC_HEADER;

int update_active_pfm(struct pfr_manifest *manifest)
{
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();
	int status = 0;
	uint32_t capsule_offset;

	if (manifest->state == FIRMWARE_RECOVERY)
		capsule_offset = manifest->recovery_address;
	else
		capsule_offset = manifest->staging_address;

	// Adjusting capsule offset size to PFM Signing chain
	capsule_offset += PFM_SIG_BLOCK_SIZE;

	spi_flash->spi.device_id[0] = manifest->image_type;
	// Updating PFM from capsule to active region
	status = flash_copy_and_verify((struct spi_flash *)&spi_flash->spi, manifest->active_pfm_addr,
			capsule_offset, BLOCK_SIZE);
	if (status != Success)
		return Failure;

	DEBUG_PRINTF("Active PFM Updated!!");

	return Success;
}

int decompression_erase(uint32_t image_type, uint32_t start_addr, uint32_t end_addr,
		uint32_t active_bitmap)
{
	uint32_t region_start_bit = start_addr / PAGE_SIZE;
	uint32_t region_end_bit = end_addr / PAGE_SIZE;
	int sector_sz = pfr_spi_get_block_size(image_type);
	uint8_t active_bitmap_byte[PAGE_SIZE];
	uint32_t erase_start_bit = 0xffffffff;
	bool support_block_erase = false;
	uint32_t bit_in_bitmap;
	uint32_t erase_bits;

	if (pfr_spi_read(image_type, active_bitmap, sizeof(active_bitmap_byte),
				active_bitmap_byte)) {
		DEBUG_PRINTF("Faild to get bitmap infromation");
		return Failure;
	}

	if (sector_sz == BLOCK_SIZE)
		support_block_erase = true;

	for (bit_in_bitmap = region_start_bit; bit_in_bitmap < region_end_bit; bit_in_bitmap++) {
		if (active_bitmap_byte[bit_in_bitmap >> 3] & (1 << (7 - (bit_in_bitmap % 8)))) {
			if (erase_start_bit == 0xffffffff)
				erase_start_bit = bit_in_bitmap;
		} else {
			if (erase_start_bit != 0xffffffff) {
				erase_bits = bit_in_bitmap - erase_start_bit;
				if (erase_bits) {
					pfr_spi_erase_region(image_type,
							support_block_erase,
							erase_start_bit * PAGE_SIZE,
							erase_bits * PAGE_SIZE);
					erase_start_bit = 0xffffffff;
				}
			}
		}
	}
	if (erase_start_bit != 0xffffffff) {
		start_addr = erase_start_bit * PAGE_SIZE;
		pfr_spi_erase_region(image_type, support_block_erase,
				start_addr, end_addr - start_addr);
	}

	return Success;
}

int decompression_write(uint32_t image_type,
		uint32_t decomp_src_addr,
		uint32_t start_addr,
		uint32_t end_addr,
		uint32_t comp_bitmap)
{
	uint32_t region_start_bit = start_addr / PAGE_SIZE;
	uint32_t region_end_bit = end_addr / PAGE_SIZE;
	uint8_t comp_bitmap_byte[PAGE_SIZE];
	uint32_t dest_addr = start_addr;
	uint32_t bitmap_byte_idx = 0;
	uint32_t copy_this_page;
	uint32_t cur_bit = 0;
	uint16_t bit_mask;

	if (pfr_spi_read(image_type, comp_bitmap, sizeof(comp_bitmap_byte), comp_bitmap_byte)) {
		DEBUG_PRINTF("Faild to get bitmap infromation");
		return Failure;
	}

	while (cur_bit < region_end_bit) {
		for (bit_mask = 0x80; bit_mask > 0; bit_mask >>= 1) {
			copy_this_page = comp_bitmap_byte[bitmap_byte_idx] & bit_mask;

			if ((region_start_bit <= cur_bit) && (cur_bit < region_end_bit)) {
				if (copy_this_page) {
					if (pfr_spi_page_read_write(image_type,
								decomp_src_addr, dest_addr))
						return Failure;
				}
				dest_addr += PAGE_SIZE;
			}

			if (copy_this_page)
				decomp_src_addr += PAGE_SIZE;

			cur_bit++;
		}
		bitmap_byte_idx++;
	}

	return Success;
}

int decompress_spi_region(struct pfr_manifest *manifest, PBC_HEADER *pbc,
		uint32_t pbc_offset, uint32_t start_addr, uint32_t end_addr)
{
	uint32_t image_type = manifest->image_type;
	uint32_t decomp_src_addr;
	uint32_t active_bitmap;
	uint32_t comp_bitmap;
	uint32_t bitmap_size;
	int status;

	bitmap_size = pbc->bitmap_nbit / 8;

	// Supported decompression adrress range is 0 - 256MB
	if (bitmap_size > (2 * PAGE_SIZE)) {
		DEBUG_PRINTF("bitmap size is too big");
		return Failure;
	}

	active_bitmap = pbc_offset + sizeof(PBC_HEADER);
	comp_bitmap = active_bitmap + bitmap_size;
	decomp_src_addr = comp_bitmap + bitmap_size;

	if (decompression_erase(image_type, start_addr, end_addr, active_bitmap))
		return Failure;

	status = decompression_write(image_type, decomp_src_addr, start_addr, end_addr,
			comp_bitmap);

	return status;
}

bool is_spi_region_static(PFM_SPI_DEFINITION *spi_region_def)
{
	return (spi_region_def->ProtectLevelMask.ReadAllowed &&
		spi_region_def->ProtectLevelMask.WriteAllowed == 0);
}

bool is_spi_region_dynamic(PFM_SPI_DEFINITION *spi_region_def)
{
	return (spi_region_def->ProtectLevelMask.ReadAllowed &&
		spi_region_def->ProtectLevelMask.WriteAllowed);
}

bool is_pbc_valid(PBC_HEADER *pbc)
{
	if (pbc->tag != PBC_COMPRESSION_TAG) {
		DEBUG_PRINTF("PBC compression tag is invalid");
		return false;
	}

	if (pbc->version != PBC_VERSION) {
		DEBUG_PRINTF("PBC version is invalid");
		return false;
	}

	if (pbc->page_size != PBC_PAGE_SIZE) {
		DEBUG_PRINTF("PBC page size is invalid");
		return false;
	}

	if (pbc->bitmap_nbit % 8){
		DEBUG_PRINTF("PBC bitmap size is invalid");
		return false;
	}

	return true;
}

#if defined(CONFIG_SEAMLESS_UPDATE)
int get_total_pfm_fvm_size(struct pfr_manifest *manifest, uint32_t signed_pfm_offset,
		uint32_t cap_pfm_body_start_addr, uint32_t cap_pfm_body_end_addr)
{
	PFM_SPI_DEFINITION spi_def;
	PFM_FVM_ADDRESS_DEFINITION *fvm_def;
	uint32_t last_fvm_start_addr = 0;
	uint32_t image_type = manifest->image_type;
	uint32_t cap_pfm_body_offset = cap_pfm_body_start_addr;

	while (cap_pfm_body_offset < cap_pfm_body_end_addr) {
		pfr_spi_read(image_type, cap_pfm_body_offset, sizeof(PFM_SPI_DEFINITION),
				(uint8_t *)&spi_def);
		if (spi_def.PFMDefinitionType == SMBUS_RULE) {
			cap_pfm_body_offset += sizeof(PFM_SMBUS_RULE);
		} else if (spi_def.PFMDefinitionType == SPI_REGION) {
			if (spi_def.HashAlgorithmInfo.SHA256HashPresent ||
			    spi_def.HashAlgorithmInfo.SHA384HashPresent) {
				cap_pfm_body_offset += sizeof(PFM_SPI_DEFINITION);
				cap_pfm_body_offset += (manifest->hash_curve == secp384r1) ?
					SHA384_SIZE : SHA256_SIZE;
			} else {
				cap_pfm_body_offset += SPI_REGION_DEF_MIN_SIZE;
			}
		} else if (spi_def.PFMDefinitionType == FVM_ADDR_DEF) {
			fvm_def = (PFM_FVM_ADDRESS_DEFINITION *)&spi_def;
			if (fvm_def->FVMAddress > last_fvm_start_addr)
				last_fvm_start_addr = fvm_def->FVMAddress;

			cap_pfm_body_offset += sizeof(PFM_FVM_ADDRESS_DEFINITION);
		} else if (spi_def.PFMDefinitionType == FVM_CAP) {
			cap_pfm_body_offset += sizeof(FVM_CAPABLITIES);
		} else {
			break;
		}
	}

	uint32_t total_pfm_fvm_size;
	// Get length from the header of the last fvm.
	if (last_fvm_start_addr) {
		PFR_AUTHENTICATION_BLOCK0 signed_fvm;
		uint32_t last_fvm_start_addr_in_pfm =
			last_fvm_start_addr - manifest->active_pfm_addr;
		uint32_t last_signed_fvm_offset = signed_pfm_offset + last_fvm_start_addr_in_pfm;

		pfr_spi_read(image_type, last_signed_fvm_offset, sizeof(PFR_AUTHENTICATION_BLOCK0),
				(uint8_t *)&signed_fvm);
		total_pfm_fvm_size = last_fvm_start_addr_in_pfm + signed_fvm.PcLength;
	} else {
		total_pfm_fvm_size = manifest->pc_length;
	}

	return total_pfm_fvm_size;
}

int decompress_fvm_spi_region(struct pfr_manifest *manifest, PBC_HEADER *pbc,
		uint32_t pbc_offset, uint32_t cap_fvm_offset,
		DECOMPRESSION_TYPE_MASK_ENUM decomp_type)
{
	FVM_STRUCTURE fvm;
	PFM_SPI_DEFINITION spi_def;
	uint32_t fvm_body_offset;
	uint32_t image_type = manifest->image_type;
	uint32_t fvm_body_end_addr;

	if (pfr_spi_read(image_type, cap_fvm_offset, sizeof(FVM_STRUCTURE),
			(uint8_t *)&fvm))
		return Failure;
	fvm_body_offset = cap_fvm_offset + sizeof(FVM_STRUCTURE);
	fvm_body_end_addr = fvm_body_offset + fvm.Length - sizeof(FVM_ADDR_DEF);

	while (fvm_body_offset < fvm_body_end_addr) {
		pfr_spi_read(image_type, fvm_body_offset, sizeof(PFM_SPI_DEFINITION),
				(uint8_t *)&spi_def);

		if (spi_def.PFMDefinitionType == SPI_REGION) {
			if (is_spi_region_static(&spi_def)) {
				if (decomp_type & DECOMPRESSION_STATIC_REGIONS_MASK) {
					if (decompress_spi_region(manifest, pbc,
								pbc_offset,
								spi_def.RegionStartAddress,
								spi_def.RegionEndAddress))
						return Failure;
				}
			} else if (is_spi_region_dynamic(&spi_def) &&
				   spi_def.RegionStartAddress != manifest->staging_address) {
				if (decomp_type & DECOMPRESSION_DYNAMIC_REGIONS_MASK) {
					if (decompress_spi_region(manifest, pbc,
								pbc_offset,
								spi_def.RegionStartAddress,
								spi_def.RegionEndAddress))
						return Failure;
				}
			}

			if (spi_def.HashAlgorithmInfo.SHA256HashPresent ||
			    spi_def.HashAlgorithmInfo.SHA384HashPresent) {
				fvm_body_offset += sizeof(PFM_SPI_DEFINITION);
				fvm_body_offset += (manifest->hash_curve == secp384r1) ?
					SHA384_SIZE : SHA256_SIZE;
			} else {
				fvm_body_offset += SPI_REGION_DEF_MIN_SIZE;
			}
		} else if (spi_def.PFMDefinitionType == FVM_CAP) {
			fvm_body_offset += sizeof(FVM_CAPABLITIES);
		} else {
			break;
		}
	}

	return Success;
}

int decompress_fv_capsule(struct pfr_manifest *manifest)
{
	uint32_t image_type = manifest->image_type;
	int sector_sz = pfr_spi_get_block_size(image_type);
	bool support_block_erase = (sector_sz == BLOCK_SIZE) ? true : false;
	uint32_t read_address = manifest->staging_address;
	uint32_t signed_fvm_offset = read_address + PFM_SIG_BLOCK_SIZE;
	uint32_t cap_fvm_offset = signed_fvm_offset + PFM_SIG_BLOCK_SIZE;
	uint32_t pbc_offset = cap_fvm_offset + manifest->pc_length;
	PBC_HEADER pbc;

	if (manifest->target_fvm_addr == 0)
		return Failure;

	// Erase and update active FVM region.
	pfr_spi_erase_region(image_type, support_block_erase, manifest->target_fvm_addr,
			manifest->pc_length);
	pfr_spi_page_read_write(image_type, signed_fvm_offset , manifest->target_fvm_addr);

	if(pfr_spi_read(image_type, pbc_offset, sizeof(PBC_HEADER), (uint8_t *)&pbc))
		return Failure;

	if (decompress_fvm_spi_region(manifest, &pbc, pbc_offset, cap_fvm_offset,
				DECOMPRESSION_STATIC_REGIONS_MASK))
		return Failure;

	return Success;
}
#endif

int decompress_capsule(struct pfr_manifest *manifest, DECOMPRESSION_TYPE_MASK_ENUM decomp_type)
{
	uint32_t image_type = manifest->image_type;
	uint32_t read_address = (manifest->state == FIRMWARE_RECOVERY) ?
		manifest->recovery_address : manifest->staging_address;
	uint32_t signed_pfm_offset = read_address + PFM_SIG_BLOCK_SIZE;
	uint32_t cap_pfm_offset = signed_pfm_offset + PFM_SIG_BLOCK_SIZE;
	uint32_t cap_pfm_body_offset = cap_pfm_offset + sizeof(PFM_STRUCTURE_1);
	uint32_t cap_pfm_body_start_addr = cap_pfm_body_offset;
	uint32_t cap_pfm_body_end_addr;
	uint32_t pbc_offset;
	uint32_t pfm_size;
	PFM_STRUCTURE_1 pfm_header;
	PFM_SPI_DEFINITION spi_def;
	PBC_HEADER pbc;

	if(pfr_spi_read(image_type, cap_pfm_offset, sizeof(PFM_STRUCTURE_1), (uint8_t *)&pfm_header))
		return Failure;

	cap_pfm_body_end_addr = cap_pfm_body_offset + pfm_header.Length - sizeof(PFM_STRUCTURE_1);

#if defined(CONFIG_SEAMLESS_UPDATE)
	pfm_size = get_total_pfm_fvm_size(manifest, signed_pfm_offset,
			cap_pfm_body_start_addr, cap_pfm_body_end_addr);
#else
	pfm_size = manifest->pc_length;
#endif
	pbc_offset = cap_pfm_offset + pfm_size;

	if(pfr_spi_read(image_type, pbc_offset, sizeof(PBC_HEADER), (uint8_t *)&pbc))
		return Failure;

	if (!is_pbc_valid(&pbc))
		return Failure;

	DEBUG_PRINTF("Decompressing capsule from %s region...",
			(manifest->state == FIRMWARE_RECOVERY) ? "recovery" : "staging");

	while (cap_pfm_body_offset < cap_pfm_body_end_addr) {
		pfr_spi_read(image_type, cap_pfm_body_offset, sizeof(PFM_SPI_DEFINITION),
				(uint8_t *)&spi_def);
		if (spi_def.PFMDefinitionType == SMBUS_RULE) {
			cap_pfm_body_offset += sizeof(PFM_SMBUS_RULE);
		} else if (spi_def.PFMDefinitionType == SPI_REGION) {
			if (is_spi_region_static(&spi_def)) {
				if (decomp_type & DECOMPRESSION_STATIC_REGIONS_MASK)
					if (decompress_spi_region(manifest, &pbc,
								pbc_offset,
								spi_def.RegionStartAddress,
								spi_def.RegionEndAddress))
						return Failure;
			} else if (is_spi_region_dynamic(&spi_def) &&
				   spi_def.RegionStartAddress != manifest->staging_address) {
				if (decomp_type & DECOMPRESSION_DYNAMIC_REGIONS_MASK)
					if (decompress_spi_region(manifest, &pbc,
								pbc_offset,
								spi_def.RegionStartAddress,
								spi_def.RegionEndAddress))
						return Failure;
			}

			if (spi_def.HashAlgorithmInfo.SHA256HashPresent ||
			    spi_def.HashAlgorithmInfo.SHA384HashPresent) {
				cap_pfm_body_offset += sizeof(PFM_SPI_DEFINITION);
				cap_pfm_body_offset += (manifest->hash_curve == secp384r1) ?
					SHA384_SIZE : SHA256_SIZE;
			} else {
				cap_pfm_body_offset += SPI_REGION_DEF_MIN_SIZE;
			}
		}
#if defined(CONFIG_SEAMLESS_UPDATE)
		else if (spi_def.PFMDefinitionType == FVM_ADDR_DEF) {
			PFM_FVM_ADDRESS_DEFINITION *fvm_def =
				(PFM_FVM_ADDRESS_DEFINITION *)&spi_def;
			uint32_t fvm_offset_in_pfm;
			uint32_t cap_fvm_offset;

			fvm_offset_in_pfm = fvm_def->FVMAddress - manifest->active_pfm_addr;
			cap_fvm_offset = cap_pfm_offset + fvm_offset_in_pfm;
			if (decompress_fvm_spi_region(manifest, &pbc, pbc_offset, cap_fvm_offset,
					decomp_type))
				return Failure;
			cap_pfm_body_offset += sizeof(PFM_FVM_ADDRESS_DEFINITION);
		} else if (spi_def.PFMDefinitionType == FVM_CAP) {
			cap_pfm_body_offset += sizeof(FVM_CAPABLITIES);
		}
#endif
		else {
			break;
		}
	}

	if (decomp_type & DECOMPRESSION_STATIC_REGIONS_MASK)
		update_active_pfm(manifest);

	return Success;
}

