/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <stdint.h>
#include <posix/time.h>
#include "state_machine/common_smc.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_pfm_manifest.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#if PF_UPDATE_DEBUG
#define DEBUG_PRINTF LOG_INF
#else
#define DEBUG_PRINTF(...)
#endif

typedef struct
{
	uint32_t tag;
	uint32_t version;
	uint32_t page_size;
	uint32_t pattern_size;
	uint32_t pattern;
	uint32_t bitmap_nbit;
	uint32_t payload_len;
	uint32_t _reserved[25];
} PBC_HEADER;

int decompression_erase_region(uint32_t image_type,
		bool support_block_erase, uint32_t start_addr, uint32_t nbytes)
{
	uint32_t erase_addr = start_addr;
	uint32_t end_addr = start_addr + nbytes;

	while(erase_addr < end_addr) {
		if (support_block_erase && ((end_addr - erase_addr) >= BLOCK_SIZE) &&
				!(erase_addr & 0xffff)) {
			if (pfr_spi_erase_block(image_type, erase_addr))
				return Failure;
			erase_addr += BLOCK_SIZE;
		} else {
			if (pfr_spi_erase_4k(image_type, erase_addr))
				return Failure;
			erase_addr += PBC_PAGE_SIZE;
		}
	}

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
			if (erase_start_bit != 0xffffffff)
				erase_bits = bit_in_bitmap - erase_start_bit;
			if (erase_bits) {
				decompression_erase_region(image_type,
						support_block_erase,
						erase_start_bit * PAGE_SIZE,
						erase_bits * PAGE_SIZE);
				erase_start_bit = 0xffffffff;
			}
		}
	}
	if (erase_start_bit != 0xffffffff) {
		start_addr = erase_start_bit * PAGE_SIZE;
		decompression_erase_region(image_type, support_block_erase,
				start_addr, end_addr - start_addr);
	}
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

	DEBUG_PRINTF("Writing...");
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
		uint32_t start_addr, uint32_t end_addr)
{
	uint32_t image_type = manifest->image_type;
	uint32_t read_address = (manifest->state == UPDATE) ?
		manifest->staging_address : manifest->recovery_address;
	uint32_t cap_pfm_offset = read_address + PFM_SIG_BLOCK_SIZE * 2;
	uint32_t pbc_offset = cap_pfm_offset + manifest->pc_length;
	uint32_t decomp_src_addr;
	uint32_t active_bitmap;
	uint32_t comp_bitmap;
	uint32_t bitmap_size;
	int status;

	bitmap_size = pbc->bitmap_nbit / 8;

	if (bitmap_size > PAGE_SIZE) {
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

int decompress_capsule(struct pfr_manifest *manifest, DECOMPRESSION_TYPE_MASK_ENUM decomp_type)
{
	uint32_t image_type = manifest->image_type;
	uint32_t read_address = (manifest->state == UPDATE) ?
		manifest->staging_address : manifest->recovery_address;
	uint32_t cap_pfm_offset = read_address + PFM_SIG_BLOCK_SIZE * 2;
	uint32_t pbc_offset = cap_pfm_offset + manifest->pc_length;
	uint32_t cap_pfm_body_offset = cap_pfm_offset + sizeof(PFM_STRUCTURE_1);
	PFM_SPI_DEFINITION spi_def;
	PBC_HEADER pbc;

	if(pfr_spi_read(image_type, pbc_offset, sizeof(PBC_HEADER), &pbc))
		return Failure;

	if (!is_pbc_valid(&pbc))
		return Failure;

	while (1) {
		pfr_spi_read(image_type, cap_pfm_body_offset, sizeof(PFM_SPI_DEFINITION), &spi_def);
		if (spi_def.PFMDefinitionType == SMBUS_RULE) {
			cap_pfm_body_offset += sizeof(PFM_SMBUS_RULE);
		} else if (spi_def.PFMDefinitionType == SPI_REGION) {
			if (is_spi_region_static(&spi_def)) {
				if (decomp_type & DECOMPRESSION_STATIC_REGIONS_MASK)
					decompress_spi_region(manifest, &pbc,
							spi_def.RegionStartAddress,
							spi_def.RegionEndAddress);
			} else if (is_spi_region_dynamic(&spi_def) &&
				   spi_def.RegionStartAddress != manifest->staging_address) {
				if (decomp_type & DECOMPRESSION_DYNAMIC_REGIONS_MASK)
					decompress_spi_region(manifest, &pbc,
							spi_def.RegionStartAddress,
							spi_def.RegionEndAddress);

			}

			if (spi_def.HashAlgorithmInfo.SHA256HashPresent ||
			    spi_def.HashAlgorithmInfo.SHA384HashPresent) {
				cap_pfm_body_offset += sizeof(PFM_SPI_DEFINITION);
				cap_pfm_body_offset += (manifest->hash_curve == secp384r1) ?
					SHA384_SIZE : SHA256_SIZE;
			} else {
				cap_pfm_body_offset += SPI_REGION_DEF_MIN_SIZE;
			}
		} else {
			break;
		}
	}

	return Success;
}

