/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include "pfr_recovery.h"
#include "StateMachineAction/StateMachineActions.h"
#include "state_machine/common_smc.h"
#include "pfr/pfr_common.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "include/SmbusMailBoxCom.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#undef DEBUG_PRINTF
#if PF_UPDATE_DEBUG
#define DEBUG_PRINTF LOG_INF
#else
#define DEBUG_PRINTF(...)
#endif

int recover_image(void *AoData, void *EventContext)
{

	int status = 0;
	AO_DATA *ActiveObjectData = (AO_DATA *) AoData;
	EVENT_CONTEXT *EventData = (EVENT_CONTEXT *) EventContext;

	// init_pfr_manifest();
	struct pfr_manifest *pfr_manifest = get_pfr_manifest();

	pfr_manifest->state = RECOVERY;

	if (EventData->image == BMC_EVENT) {
		// BMC SPI
		DEBUG_PRINTF("Image Type: BMC ");
		pfr_manifest->image_type = BMC_TYPE;

	} else  {
		// PCH SPI
		DEBUG_PRINTF("Image Type: PCH ");
		pfr_manifest->image_type = PCH_TYPE;
	}

	if (ActiveObjectData->RecoveryImageStatus != Success) {
		// status = pfr_staging_verify(pfr_manifest);
		status = status = pfr_manifest->update_fw->base->verify(pfr_manifest, NULL, NULL);
		if (status != Success) {
			DEBUG_PRINTF("PFR Staging Area Corrupted");
			if (ActiveObjectData->ActiveImageStatus != Success) {
				SetMajorErrorCode(pfr_manifest->image_type == BMC_TYPE ? BMC_AUTH_FAIL : PCH_AUTH_FAIL);
				SetMinorErrorCode(ACTIVE_RECOVERY_STAGING_AUTH_FAIL);
				if (pfr_manifest->image_type == PCH_TYPE) {
					status = pfr_staging_pch_staging(pfr_manifest);
					if (status != Success)
						return Failure;
				} else
					return Failure;
			} else
				return Failure;
		}
		if (ActiveObjectData->ActiveImageStatus == Success) {
			status = pfr_active_recovery_svn_validation(pfr_manifest);
			if (status != Success)
				return Failure;
		}

		status = pfr_recover_recovery_region(pfr_manifest->image_type, pfr_manifest->address, pfr_manifest->recovery_address);
		if (status != Success)
			return Failure;

		ActiveObjectData->RecoveryImageStatus = Success;
		return VerifyRecovery;
	}

	if (ActiveObjectData->ActiveImageStatus != Success) {
		status = pfr_recover_active_region(pfr_manifest);
		if (status != Success)
			return Failure;

		ActiveObjectData->ActiveImageStatus = Success;
		return VerifyActive;
	}

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
		    struct signature_verification *verification, uint8_t *hash_out, size_t hash_length,
		    struct pfm_manager *pfm)
{

	return intel_pfr_recovery_verify(image, hash, verification, hash_out, hash_length, pfm);
}

/**
 * Get the SHA-256 hash of the recovery image data, not including the signature.
 *
 * @param image The recovery image to query.
 * @param hash The hash engine to use for generating the hash.
 * @param hash_out Output buffer for the manifest hash.
 * @param hash_length Length of the hash output buffer.
 *
 * @return 0 if the hash was calculated successfully or an error code.
 */
int recovery_get_hash(struct recovery_image *image, struct hash_engine *hash, uint8_t *hash_out,
		      size_t hash_length)
{

	ARG_UNUSED(image);
	ARG_UNUSED(hash);
	ARG_UNUSED(hash_out);
	ARG_UNUSED(hash_length);

	return Success;
}

/**
 * Get the version of the recovery image.
 *
 * @param image The recovery image to query.
 * @param version The buffer to hold the version ID.
 * @param len The output buffer length.
 *
 * @return 0 if the ID was successfully retrieved or an error code.
 */
int recovery_get_version(struct recovery_image *image, char *version, size_t len)
{

	ARG_UNUSED(image);
	ARG_UNUSED(version);
	ARG_UNUSED(len);

	return Success;
}

/**
 * Apply the recovery image to host flash.  It is assumed that the host flash region is already
 * blank.
 *
 * @param image The recovery image to query.
 * @param flash The flash device to write the recovery image to.
 *
 * @return 0 if applying the recovery image to host flash was successful or an error code.
 */
int recovery_apply_to_flash(struct recovery_image *image, struct spi_flash *flash)
{

	int status = 0;
	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) image;

	return intel_pfr_recover_update_action(pfr_manifest);
}

void init_recovery_manifest(struct recovery_image *image)
{
	image->verify = recovery_verify;
	image->get_hash = recovery_get_hash;
	image->get_version = recovery_get_version;
	image->apply_to_flash = recovery_apply_to_flash;

}
