/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <assert.h>

#include "include/definitions.h"
#include "manifestProcessor.h"
#include "pfr/pfr_common.h"
#include "common/common.h"
#include "firmware/app_image.h"

LOG_MODULE_REGISTER(manifest, CONFIG_LOG_DEFAULT_LEVEL);

int initializeManifestProcessor(void)
{
	int status = 0;

#if 0
#if defined(CONFIG_CERBERUS_PFR)
	status = manifest_flash_init(getManifestFlashInstance(), getFlashDeviceInstance(), PFM_FLASH_MANIFEST_ADDRESS, PFM_V2_MAGIC_NUM);
	if (status)
		return status;
#endif
#endif

	init_pfr_bases();

	return status;
}

void uninitializeManifestProcessor(void)
{
	manifest_flash_release(getManifestFlashInstance());
}

