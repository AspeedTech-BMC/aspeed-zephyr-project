/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_CERBERUS_PFR)
#include <logging/log.h>
#include <storage/flash_map.h>
#include "common/common.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_ufm.h"
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "cerberus_pfr_recovery.h"
#include "manifest/pfm/pfm_manager.h"
#include "cerberus_pfr_authentication.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_verification.h"
#include "flash/flash_util.h"
#include "flash/flash_aspeed.h"
#include "pfr/pfr_util.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#if PF_UPDATE_DEBUG
#define DEBUG_PRINTF printk
#else
#define DEBUG_PRINTF(...)
#endif

int pfr_active_recovery_svn_validation(struct pfr_manifest *manifest)
{
	return Success;
}

int pfr_recover_active_region(struct pfr_manifest *manifest)
{
	struct recovery_header recovery_header;
	int status = Success;
	uint32_t sig_address, recovery_offset, data_offset, start_address, erase_address;
	uint32_t section_length;
	struct recovery_section recovery_section;
	uint8_t platform_length;
	uint32_t source_address;

	if(manifest->image_type == BMC_TYPE){
		get_provision_data_in_flash(BMC_RECOVERY_REGION_OFFSET,
				(uint8_t *)&source_address, sizeof(source_address));
	}else if(manifest->image_type == PCH_TYPE){
		get_provision_data_in_flash(PCH_RECOVERY_REGION_OFFSET,
				(uint8_t *)&source_address, sizeof(source_address));
	}else{
		return Failure;
	}

	//read recovery header
	status = pfr_spi_read(manifest->image_type, source_address, sizeof(recovery_header),
			(uint8_t *)&recovery_header);
	sig_address = recovery_header.image_length - recovery_header.sign_length;
	recovery_offset = source_address + sizeof(recovery_header);
	status = pfr_spi_read(manifest->image_type, recovery_offset, sizeof(platform_length),
			(uint8_t *)&platform_length);
	recovery_offset = recovery_offset + platform_length + 1;

	int sector_sz = pfr_spi_get_block_size(manifest->image_type);
	bool support_block_erase = (sector_sz == BLOCK_SIZE);

	while(recovery_offset != sig_address)
	{
		status = pfr_spi_read(manifest->image_type, recovery_offset,
				sizeof(recovery_section), (uint8_t *)&recovery_section);
		if(recovery_section.magic_number != RECOVERY_SECTION_MAGIC)
		{
			DEBUG_PRINTF("Recovery Section not matched..\n");
			break;
		}
		start_address = recovery_section.start_addr;
		section_length = recovery_section.section_length;
		erase_address = start_address;
		recovery_offset = recovery_offset + sizeof(recovery_section);
		data_offset = recovery_offset;

		if (pfr_spi_erase_region(manifest->image_type, support_block_erase, erase_address,
					section_length))
			return Failure;

		if (pfr_spi_region_read_write_between_spi(manifest->image_type, data_offset,
					manifest->image_type, start_address, section_length))
			return Failure;

		recovery_offset = recovery_offset + section_length;
	}

	DEBUG_PRINTF("Repair success\r\n");

	return Success;
}

int active_region_pfm_update(struct pfr_manifest *manifest)
{
	return Success;
}

int pfr_staging_pch_staging(struct pfr_manifest *manifest)
{
	int status = Success;

	uint32_t source_address;
	uint32_t target_address;

	status = ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
			sizeof(source_address));
	if (status != Success)
		return Failure;

	status = ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&target_address,
			sizeof(target_address));
	if(status != Success)
		return Failure;

	source_address += CONFIG_BMC_STAGING_SIZE;
	int sector_sz = pfr_spi_get_block_size(manifest->image_type);
	bool support_block_erase = (sector_sz == BLOCK_SIZE);

	LOG_INF("Copying staging region from BMC addr: 0x%08x to PCH addr: 0x%08x",
			source_address, target_address);

	if (pfr_spi_erase_region(PCH_TYPE, support_block_erase, target_address,
				CONFIG_PCH_STAGING_SIZE))
		return Failure;

	if (pfr_spi_region_read_write_between_spi(BMC_TYPE, source_address, PCH_TYPE,
				target_address, CONFIG_PCH_STAGING_SIZE))
		return Failure;

	if (manifest->state == FIRMWARE_RECOVERY) {
		LOG_INF("PCH staging region verification");
		status = manifest->update_fw->base->verify((struct firmware_image *)manifest,
				NULL, NULL);
		if (status != Success)
			return Failure;
	}

	LOG_INF("PCH Staging region Update completed");

	return Success;
}

int pfr_recover_update_action(struct pfr_manifest *manifest)
{
	return Success;
}

/**
 * Verify if the recovery image is valid.
 *
 * @param image The recovery image to validate.
 * @param hash The hash engine to use for validation.
 * @param verification Verification instance to use to verify the recovery image signature.
 * @param hash_out Optional output buffer for the recovery image hash calculated during
 * verification.  Set to null to not return the hash.
 * @param hash_length Length of the hash output buffer.
 * @param pfm_manager The PFM manager to use for validation.
 *
 * @return 0 if the recovery image is valid or an error code.
 */
int recovery_verify(struct recovery_image *image, struct hash_engine *hash,
		    struct signature_verification *verification, uint8_t *hash_out,
		    size_t hash_length, struct pfm_manager *pfm)
{
	ARG_UNUSED(hash);
	ARG_UNUSED(verification);
	ARG_UNUSED(hash_out);
	ARG_UNUSED(hash_length);
	ARG_UNUSED(pfm);
	struct pfr_manifest *manifest = (struct pfr_manifest *)image;
	init_stage_and_recovery_offset(manifest);
	manifest->address = manifest->recovery_address;
	return cerberus_pfr_verify_image(manifest);
}

int recovery_apply_to_flash(struct recovery_image *image, struct spi_flash *flash)
{
	// TODO
	return Success;
}
#endif // CONFIG_CERBERUS_PFR
