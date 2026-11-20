/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>
#include <flash/flash_aspeed.h>

#include "pfr/pfr_common.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_verification.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_pfm_manifest.h"
#include "pfr/pfr_ufm.h"
#include "intel_pfr_sig_scheme.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int pfr_recovery_verify(struct pfr_manifest *manifest)
{
	int status = 0;
	uint32_t read_address = 0;

	LOG_INF("Verify recovery");

	// Recovery region verification
	switch (manifest->image_type) {
	case BMC_TYPE:
		ufm_read(PROVISION_UFM, BMC_RECOVERY_REGION_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
		break;
	case PCH_TYPE:
		ufm_read(PROVISION_UFM, PCH_RECOVERY_REGION_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
		break;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
#if (CONFIG_AFM_SPEC_VERSION == 4)
	case ROT_EXT_AFM_RC_1:
	case ROT_EXT_AFM_RC_2:
		break;
#elif (CONFIG_AFM_SPEC_VERSION == 3)
	case AFM_TYPE:
		read_address = CONFIG_BMC_AFM_RECOVERY_OFFSET;
		manifest->image_type = BMC_TYPE;
		break;
#endif
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	case CPLD_TYPE:
		manifest->image_type = ROT_EXT_CPLD_RC;
		break;
#endif
	default:
		LOG_ERR("Incorrect manifest image_type");
		return Failure;
	}

	manifest->address = read_address;

	LOG_INF("Verifying capsule signature, address=0x%08x", manifest->address);
	// Block0-Block1 verification
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
			manifest->verification->base, manifest->pfr_hash->hash_out,
			manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Verify recovery capsule failed");
		return Failure;
	}

	// Recovery region PFM verification
	manifest->address += intel_pfr_sig_block_size(manifest);
	LOG_INF("Signature scheme = %s", manifest->sig_scheme->name);
	LOG_INF("Verifying PFM signature, address=0x%08x", manifest->address);
	// manifest verification
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
	uint32_t read_address = 0;

	switch (manifest->image_type) {
	case BMC_TYPE:
		get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
		break;
	case PCH_TYPE:
		get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
		break;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
#if (CONFIG_AFM_SPEC_VERSION == 4)
	case ROT_EXT_AFM_ACT_1:
	case ROT_EXT_AFM_ACT_2:
	case ROT_INTERNAL_AFM:
		break;
#elif (CONFIG_AFM_SPEC_VERSION == 3)
	case ROT_INTERNAL_AFM:
		break;
#endif
#endif
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	case CPLD_TYPE:
		manifest->image_type = ROT_EXT_CPLD_ACT;
		manifest->address = read_address;
		LOG_INF("Verifying capsule signature, address=0x%08x", manifest->address);
		if (manifest->pfr_authentication->online_update_cap_verify(manifest)) {
			LOG_ERR("Verify BMC's CPLD active region failed");
			return Failure;
		}
		LOG_INF("Verify CPLD active region success");
		return Success;
#endif
	default:
		LOG_ERR("Unsupported image type %d", manifest->image_type);
		return Failure;
	}

	manifest->address = read_address;

	LOG_INF("Active Firmware Verification");
	LOG_INF("Verifying PFM signature, address=0x%08x", manifest->address);

	switch (manifest->image_type) {
	case BMC_TYPE:
	case PCH_TYPE:
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	case CPLD_TYPE:
#endif
		status = manifest->base->verify((struct manifest *)manifest, manifest->hash,
				manifest->verification->base, manifest->pfr_hash->hash_out,
				manifest->pfr_hash->length);
		break;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
#if (CONFIG_AFM_SPEC_VERSION == 4)
	case ROT_EXT_AFM_ACT_1:
	case ROT_EXT_AFM_ACT_2:
		status = verify_afm_devices(manifest);
		break;
	case ROT_INTERNAL_AFM:
		if (verify_internal_afm(manifest, BMC_SPI) ||
			verify_internal_afm(manifest, PCH_SPI))
			return Failure;

		return Success;
#elif (CONFIG_AFM_SPEC_VERSION == 3)
	case ROT_INTERNAL_AFM:
		status = verify_afm_devices(manifest);
		break;
#endif
#endif
	}
	if (status != Success) {
		LOG_ERR("Verify active PFM failed");
		return Failure;
	}

	status = get_active_pfm_version_details(manifest, read_address);
	if (status != Success)
		return Failure;

	status = pfm_spi_region_verification(manifest);
	if (status != Success) {
		LOG_ERR("Verify active SPI region failed");
		return Failure;
	}

	LOG_INF("Verify active SPI region success");
	return Success;
}

