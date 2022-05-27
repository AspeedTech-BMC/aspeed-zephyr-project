/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include "pfr/pfr_common.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_verification.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "intel_pfr_provision.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#if PF_STATUS_DEBUG
#define DEBUG_PRINTF LOG_INF
#else
#define DEBUG_PRINTF(...)
#endif


int pfr_recovery_verify(struct pfr_manifest *manifest)
{
	int status = 0;
	uint32_t read_address;

	DEBUG_PRINTF("Verify recovery");

	// Recovery region verification
	if (manifest->image_type == BMC_TYPE) {
		ufm_read(PROVISION_UFM, BMC_RECOVERY_REGION_OFFSET, &read_address, sizeof(read_address));
		manifest->pc_type = PFR_BMC_UPDATE_CAPSULE;
	} else if (manifest->image_type == PCH_TYPE) {
		ufm_read(PROVISION_UFM, PCH_RECOVERY_REGION_OFFSET, &read_address, sizeof(read_address));
		manifest->pc_type = PFR_PCH_UPDATE_CAPSULE;
	}
	manifest->address = read_address;

	// Block0-Block1 verifcation
	status = manifest->base->verify(manifest, manifest->hash, manifest->verification->base, manifest->pfr_hash->hash_out, manifest->pfr_hash->length);
	if (status != Success) {
		DEBUG_PRINTF("Verify recovery failed");
		return Failure;
	}

	if (manifest->image_type == BMC_TYPE)
		manifest->pc_type = PFR_BMC_PFM;
	else if (manifest->image_type == PCH_TYPE)
		manifest->pc_type = PFR_PCH_PFM;

	// Recovery region PFM verification
	manifest->address += PFM_SIG_BLOCK_SIZE;

	// manifest verifcation
	status = manifest->base->verify(manifest, manifest->hash, manifest->verification->base, manifest->pfr_hash->hash_out, manifest->pfr_hash->length);
	if (status != Success) {
		DEBUG_PRINTF("Verify recovery pfm failed");
		return Failure;
	}

	status = get_recover_pfm_version_details(manifest, read_address);
	if (status != Success)
		return Failure;

	DEBUG_PRINTF("Recovery Region verification success");

	return Success;
}

int pfr_active_verify(struct pfr_manifest *manifest)
{
	int status = 0;
	uint32_t read_address;

	if (manifest->image_type == BMC_TYPE) {
		get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, &read_address, sizeof(read_address));
		manifest->pc_type = PFR_BMC_PFM;
	} else if (manifest->image_type == PCH_TYPE) {
		get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, &read_address, sizeof(read_address));
		manifest->pc_type = PFR_PCH_PFM;
	}

	manifest->address = read_address;

	DEBUG_PRINTF("PFM Verification");

	LOG_INF("manifest->address=%p manifest->recovery_address=%p", manifest->address, manifest->recovery_address);
	status = manifest->base->verify(manifest, manifest->hash, manifest->verification->base, manifest->pfr_hash->hash_out, manifest->pfr_hash->length);
	if (status != Success) {
		DEBUG_PRINTF("Verify active pfm failed");
		SetMajorErrorCode(manifest->image_type == BMC_TYPE ? BMC_AUTH_FAIL : PCH_AUTH_FAIL);
		return Failure;
	}

	read_address = read_address + PFM_SIG_BLOCK_SIZE;
	status = pfm_version_set(manifest, read_address);
	if (status != Success)
		return Failure;

	status = pfm_spi_region_verification(manifest);
	if (status != Success) {
		SetMajorErrorCode(manifest->image_type == BMC_TYPE ? BMC_AUTH_FAIL : PCH_AUTH_FAIL);
		DEBUG_PRINTF("Verify active spi failed");
		return Failure;
	}

	return Success;
}



