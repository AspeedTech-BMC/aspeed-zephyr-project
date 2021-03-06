/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <storage/flash_map.h>
#include "common/common.h"
#include "pfr/pfr_ufm.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "AspeedStateMachine/common_smc.h"
#include "manifest/pfm/pfm_manager.h"
#include "intel_pfr_recovery.h"
#include "intel_pfr_pfm_manifest.h"
#include "intel_pfr_pbc.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_verification.h"
#include "intel_pfr_authentication.h"
#include "flash/flash_wrapper.h"
#include "flash/flash_util.h"
#include "Smbus_mailbox/Smbus_mailbox.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#if PF_UPDATE_DEBUG
#define DEBUG_PRINTF LOG_INF
#else
#define DEBUG_PRINTF(...)
#endif

int intel_pfr_recovery_verify(struct recovery_image *image, struct hash_engine *hash,
		struct signature_verification *verification, uint8_t *hash_out, size_t hash_length,
		struct pfm_manager *pfm)
{
	ARG_UNUSED(hash);
	ARG_UNUSED(verification);
	ARG_UNUSED(hash_out);
	ARG_UNUSED(hash_length);
	ARG_UNUSED(pfm);

	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) image;

	return pfr_recovery_verify(pfr_manifest);
}

int pfr_active_recovery_svn_validation(struct pfr_manifest *manifest)
{

	int status = 0;
	uint8_t staging_svn, active_svn;

	status = read_statging_area_pfm(manifest, &staging_svn);
	if (status != Success)
		return Failure;

	if (manifest->image_type == BMC_TYPE)
		active_svn = GetBmcPfmActiveSvn();
	else
		active_svn = GetPchPfmActiveSvn();

	if (active_svn != staging_svn) {
		DEBUG_PRINTF("SVN error");
		return Failure;
	}

	return Success;
}

int pfr_recover_recovery_region(int image_type, uint32_t source_address, uint32_t target_address)
{
	int status = 0;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();
	int sector_sz = pfr_spi_get_block_size(image_type);
	bool support_block_erase = (sector_sz == BLOCK_SIZE);
	size_t area_size = 0;

	if (image_type == BMC_TYPE)
		area_size = CONFIG_BMC_STAGING_SIZE;
	else /* if (image_type == PCH_TYPE) */
		area_size = CONFIG_PCH_STAGING_SIZE;

	spi_flash->spi.device_id[0] = image_type;
	DEBUG_PRINTF("Recovering...");
	if (pfr_spi_erase_region(image_type, support_block_erase, target_address, area_size)) {

		DEBUG_PRINTF("Recovery region erase failed");
		return Failure;
	}

	// use read_write_between spi for supporting dual flash
	if (pfr_spi_region_read_write_between_spi(image_type, source_address, image_type,
				target_address, area_size)) {
		DEBUG_PRINTF("Recovery region update failed");
		return Failure;
	}

	DEBUG_PRINTF("Recovery region update completed");

	return status;
}

int pfr_recover_active_region(struct pfr_manifest *manifest)
{
	uint32_t read_address;
	uint32_t staging_address;
	uint32_t act_pfm_offset;
	PFR_AUTHENTICATION_BLOCK0 *block0_buffer;
	uint8_t buffer[sizeof(PFR_AUTHENTICATION_BLOCK0)] = { 0 };

	DEBUG_PRINTF("Active Data Corrupted");
	if (manifest->image_type == BMC_TYPE) {
		if (ufm_read(PROVISION_UFM, BMC_RECOVERY_REGION_OFFSET, (uint8_t *)&read_address,
					sizeof(read_address)))
			return Failure;

		if (ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET,
				(uint8_t *)&staging_address, sizeof(staging_address)))
			return Failure;

		if (ufm_read(PROVISION_UFM, BMC_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	} else if (manifest->image_type == PCH_TYPE) {
		if (ufm_read(PROVISION_UFM, PCH_RECOVERY_REGION_OFFSET, (uint8_t *)&read_address,
					sizeof(read_address)))
			return Failure;

		if (ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&staging_address,
					sizeof(staging_address)))
			return Failure;

		if(ufm_read(PROVISION_UFM, PCH_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	} else {
		return Failure;
	}

	manifest->recovery_address = read_address;
	manifest->staging_address = staging_address;
	manifest->active_pfm_addr = act_pfm_offset;
	manifest->address = read_address;
	manifest->address += PFM_SIG_BLOCK_SIZE;

	if (pfr_spi_read(manifest->image_type, manifest->address,
			sizeof(PFR_AUTHENTICATION_BLOCK0), buffer)) {
		LOG_ERR("Block0: Flash read data failed");
		return Failure;
	}

	block0_buffer = (PFR_AUTHENTICATION_BLOCK0 *)buffer;
	manifest->pc_length = block0_buffer->PcLength;

	uint32_t time_start, time_end;
	time_start = k_uptime_get_32();

	if (decompress_capsule(manifest, DECOMPRESSION_STATIC_AND_DYNAMIC_REGIONS_MASK)) {
		DEBUG_PRINTF("Repair Failed");
		return Failure;
	}

	time_end = k_uptime_get_32();
	DEBUG_PRINTF("Firmware recovery completed, elapsed time = %u milliseconds",
			(time_end - time_start));

	DEBUG_PRINTF("Repair success");

	return Success;
}

int pfr_staging_pch_staging(struct pfr_manifest *manifest)
{

	int status;

	uint32_t source_address;
	uint32_t target_address;
	uint32_t image_type = manifest->image_type;

	status = ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
			sizeof(source_address));
	if (status != Success)
		return Failure;

	status = ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&target_address,
			sizeof(target_address));
	if (status != Success)
		return Failure;

	source_address += CONFIG_BMC_STAGING_SIZE;

	manifest->image_type = BMC_TYPE;
	manifest->address = source_address;
	manifest->pc_type = PFR_PCH_UPDATE_CAPSULE;

	DEBUG_PRINTF("BMC's PCH Staging Area verfication");
	DEBUG_PRINTF("Veriifying capsule signature, address=0x%08x", manifest->address);
	// manifest verifcation
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		DEBUG_PRINTF("verify failed");
		return Failure;
	}

	// Recovery region PFM verification
	manifest->address += PFM_SIG_BLOCK_SIZE;
	manifest->pc_type = PFR_PCH_PFM;
	DEBUG_PRINTF("Verifying PFM signature, address=0x%08x", manifest->address);
	// manifest verifcation
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success)
		return Failure;
	DEBUG_PRINTF("BMC's PCH Staging verification successful");
	manifest->address = target_address;
	manifest->image_type = image_type;

	int sector_sz = pfr_spi_get_block_size(image_type);
	bool support_block_erase = (sector_sz == BLOCK_SIZE);

	DEBUG_PRINTF("Copying staging region from BMC addr: 0x%08x to PCH addr: 0x%08x",
			source_address, target_address);
	if (pfr_spi_erase_region(manifest->image_type, support_block_erase, target_address,
			CONFIG_BMC_PCH_STAGING_SIZE))
		return Failure;

	if (pfr_spi_region_read_write_between_spi(BMC_TYPE, source_address, PCH_TYPE,
				target_address, CONFIG_BMC_PCH_STAGING_SIZE))
		return Failure;

	if (manifest->state == RECOVERY) {
		DEBUG_PRINTF("PCH staging region verification");
		status = manifest->update_fw->base->verify((struct firmware_image *)manifest,
				NULL, NULL);
		if (status != Success)
			return Failure;
	}

	DEBUG_PRINTF("PCH Staging region Update completed");

	return Success;
}

int intel_pfr_recover_update_action(struct pfr_manifest *manifest)
{
	ARG_UNUSED(manifest);
	return Success;
}
