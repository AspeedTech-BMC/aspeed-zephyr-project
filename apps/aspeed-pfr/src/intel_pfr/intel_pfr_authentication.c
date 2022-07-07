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
#include "intel_pfr_pfm_manifest.h"
#include "pfr/pfr_ufm.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int pfr_recovery_verify(struct pfr_manifest *manifest)
{
	int status = 0;
	uint32_t read_address;

	LOG_INF("Verify recovery");

	// Recovery region verification
	if (manifest->image_type == BMC_TYPE) {
		LOG_INF("Image Type: BMC");
		ufm_read(PROVISION_UFM, BMC_RECOVERY_REGION_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
		manifest->pc_type = PFR_BMC_UPDATE_CAPSULE;
	} else if (manifest->image_type == PCH_TYPE) {
		LOG_INF("Image Type: PCH");
		ufm_read(PROVISION_UFM, PCH_RECOVERY_REGION_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
		manifest->pc_type = PFR_PCH_UPDATE_CAPSULE;
	}

	manifest->address = read_address;

	LOG_INF("Verifying capsule signature, address=0x%08x", manifest->address);
	// Block0-Block1 verifcation
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Verify recovery capsule failed");
		return Failure;
	}

	if (manifest->image_type == BMC_TYPE)
		manifest->pc_type = PFR_BMC_PFM;
	else if (manifest->image_type == PCH_TYPE)
		manifest->pc_type = PFR_PCH_PFM;

	// Recovery region PFM verification
	manifest->address += PFM_SIG_BLOCK_SIZE;

	LOG_INF("Verifying PFM signature, address=0x%08x", manifest->address);
	// manifest verifcation
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Verify recovery PFM failed");
		return Failure;
	}

	status = get_recover_pfm_version_details(manifest, read_address);
	if (status != Success)
		return Failure;

	LOG_INF("Recovery area verification successful");

	return Success;
}

int pfr_active_verify(struct pfr_manifest *manifest)
{
	int status = 0;
	uint32_t read_address;

	if (manifest->image_type == BMC_TYPE) {
		LOG_INF("Image Type: BMC");
		get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
		manifest->pc_type = PFR_BMC_PFM;
	} else if (manifest->image_type == PCH_TYPE) {
		LOG_INF("Image Type: PCH");
		get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
		manifest->pc_type = PFR_PCH_PFM;
	}

	manifest->address = read_address;

	LOG_INF("Active Firmware Verification");
	LOG_INF("Verifying PFM signature, address=0x%08x", manifest->address);
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Verify active PFM failed");
		SetMajorErrorCode(manifest->image_type == BMC_TYPE ? BMC_AUTH_FAIL : PCH_AUTH_FAIL);
		return Failure;
	}

	read_address = read_address + PFM_SIG_BLOCK_SIZE;
	status = pfm_version_set(manifest, read_address);
	if (status != Success) {
		LOG_ERR("PFM version set failed");
		return Failure;
	}

	status = pfm_spi_region_verification(manifest);
	if (status != Success) {
		SetMajorErrorCode(manifest->image_type == BMC_TYPE ? BMC_AUTH_FAIL : PCH_AUTH_FAIL);
		LOG_ERR("Verify active SPI region failed");
		return Failure;
	}

	LOG_INF("Verify active SPI region success");
	return Success;
}



