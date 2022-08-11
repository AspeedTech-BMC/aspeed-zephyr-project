/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#if defined(CONFIG_CERBERUS_PFR)

#include "pfr/pfr_common.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include <include/definitions.h>
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_key_cancellation.h"

#if PF_STATUS_DEBUG
#define DEBUG_PRINTF printk
#else
#define DEBUG_PRINTF(...)
#endif

int pfr_recovery_verify(struct pfr_manifest *manifest)
{
	return Success;
}

int pfr_active_verify(struct pfr_manifest *manifest)
{
	printk("Active Region Verify ... \n");
	int status = 0;
	//manifest->address = PFM_FLASH_MANIFEST_ADDRESS;
	if (manifest->image_type == BMC_TYPE){
		get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, (uint8_t *)&manifest->address, sizeof(manifest->address));
	}else{
		get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)&manifest->address, sizeof(manifest->address));
	}

	printk("manifest->address:%x \r\n", manifest->address);

	status = manifest->base->verify(manifest,manifest->hash,manifest->verification->base, manifest->pfr_hash->hash_out, manifest->pfr_hash->length);

	if(status != Success){
		DEBUG_PRINTF("Verify active pfm failed\r\n");
		SetMajorErrorCode(manifest->image_type == BMC_TYPE ? BMC_AUTH_FAIL : PCH_AUTH_FAIL);
		return Failure;
	}
	status = cerberus_verify_regions(manifest);
	if(status != Success){
		SetMajorErrorCode(manifest->image_type == BMC_TYPE ? BMC_AUTH_FAIL : PCH_AUTH_FAIL);
		DEBUG_PRINTF("Verify active spi failed\r\n");
		return Failure;
	}
	DEBUG_PRINTF("Active Region verification success\r\n");
	return Success;
}

#endif // CONFIG_CERBERUS_PFR
