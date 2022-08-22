/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#if defined(CONFIG_CERBERUS_PFR)
#include <logging/log.h>
#include "pfr/pfr_common.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_authentication.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int pfr_recovery_verify(struct pfr_manifest *manifest)
{
	return Success;
}

int pfr_active_verify(struct pfr_manifest *manifest)
{
	int status = 0;

	if (manifest->image_type == BMC_TYPE) {
		get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, (uint8_t *)&manifest->address, sizeof(manifest->address));
	} else {
		get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)&manifest->address, sizeof(manifest->address));
	}

	LOG_INF("Active Firmware Verification");
	LOG_INF("Verifying PFM signature, address=0x%08x", manifest->address);
	status = manifest->base->verify((struct manifest *)manifest, manifest->hash, manifest->verification->base, manifest->pfr_hash->hash_out, manifest->pfr_hash->length);
	if (status != Success) {
		LOG_ERR("Verify active PFM failed");
		return Failure;
	}

	status = cerberus_verify_regions((struct manifest *)manifest);
	if (status != Success) {
		LOG_ERR("Verify active SPI region failed");
		return Failure;
	}

	LOG_INF("Verify active SPI region success");
	return Success;
}

#endif // CONFIG_CERBERUS_PFR
