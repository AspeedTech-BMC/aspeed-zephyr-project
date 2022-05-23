/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <assert.h>

#include "include/definitions.h"
#include "manifestProcessor.h"
#include "common/common.h"
#include "firmware/app_image.h"

LOG_MODULE_REGISTER(manifest, CONFIG_LOG_DEFAULT_LEVEL);

int initializeManifestProcessor(void)
{
	int status = 0;

	status = manifest_flash_init(getManifestFlashInstance(), getFlashDeviceInstance(), PFM_FLASH_MANIFEST_ADDRESS, PFM_V2_MAGIC_NUM);
	if (status)
		return status;

	init_pfr_manifest();
	// status = pfm_manager_flash_init(getPfmManagerFlashInstance(), getPfmFlashInstance(), getPfmFlashInstance(),
	// getHostStateManagerInstance(), get_hash_engine_instance(), getSignatureVerificationInstance());

	return status;
}

void uninitializeManifestProcessor(void)
{
	manifest_flash_release(getManifestFlashInstance());
}

int processPfmFlashManifest(void)
{
	int status = 0;
	uint8_t *hashStorage = getNewHashStorage();
	struct manifest_flash *manifest_flash = getManifestFlashInstance();

	LOG_INF("Manifest Verification\n");
	status = manifest_flash_verify(manifest_flash, get_hash_engine_instance(),
				       getSignatureVerificationInstance(), hashStorage, hashStorageLength);

	if (true == manifest_flash->manifest_valid) {
		LOG_INF("Manifest Verificaation Successful\n");

		status = perform_image_verification();
	}

	return status;
}
