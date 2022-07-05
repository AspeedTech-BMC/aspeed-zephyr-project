/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <stdint.h>
#include "pfr_ufm.h"
#include "AspeedStateMachine/common_smc.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "include/SmbusMailBoxCom.h"
#include <drivers/misc/aspeed/pfr_aspeed.h>
#include <StateMachineAction/StateMachineActions.h>
#include "pfr_common.h"
#include <flash/flash_wrapper.h>

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#undef DEBUG_PRINTF
#if PF_UPDATE_DEBUG
#define DEBUG_PRINTF LOG_INF
#else
#define DEBUG_PRINTF(...)
#endif

int handle_update_image_action(int image_type, void *AoData, void *EventContext)
{
	CPLD_STATUS cpld_update_status;
	int status;

	status = ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
	if (status != Success)
		return status;

	BMCBootHold();
	PCHBootHold();


#if SMBUS_MAILBOX_SUPPORT
	SetPlatformState(image_type == BMC_TYPE ? BMC_FW_UPDATE : (PCH_TYPE ? PCH_FW_UPDATE : CPLD_FW_UPDATE));
	if (image_type != CPLD_FW_UPDATE) {
		SetLastPanicReason(lastPanicReason(image_type));
		IncPanicEventCount();
	}
#endif

	status = update_firmware_image(image_type, AoData, EventContext);
	if (status != Success)
		return Failure;

	return Success;
}


/**
 * Update the image referenced by an instance.
 *
 * @param fw The firmware image instance to update.
 * @param flash The flash device that contains the firmware image.
 * @param base_addr The starting address of the new firmware image.
 *
 * @return 0 if the image reference was updated successfully or an error code.  Load-time
 * validation errors will generate one of the following errors:
 *              - FIRMWARE_IMAGE_INVALID_FORMAT
 *              - FIRMWARE_IMAGE_BAD_CHECKSUM
 *              - KEY_MANIFEST_INVALID_FORMAT
 *              - FIRMWARE_HEADER validation errors
 */
int firmware_image_load(struct firmware_image *fw, struct flash *flash, uint32_t base_addr)
{
	return Success;
}

/**
 * Verify the complete firmware image.  All components in the image will be fully validated.
 * This includes checking image signatures and key revocation.
 *
 * @param fw The firmware image to validate.
 * @param hash The hash engine to use for validation.
 * @param rsa The RSA engine to use for signature checking.
 *
 * @return 0 if the firmware image is valid or an error code.
 */
int firmware_image_verify(struct firmware_image *fw, struct hash_engine *hash, struct rsa_engine *rsa)
{
	return intel_pfr_update_verify(fw, hash, rsa);
}

/**
 * Get the total size of the firmware image.
 *
 * @param fw The firmware image to query.
 *
 * @return The size of the firmware image or an error code.  Use ROT_IS_ERROR to check the
 * return value.
 */
int firmware_image_get_image_size(struct firmware_image *fw)
{
	ARG_UNUSED(fw);
	return Success;
}

/**
 * Get the key manifest for the current firmware image.
 *
 * @param fw The firmware image to query.
 *
 * @return The image key manifest or null if there is an error.  The memory for the key
 * manifest is managed by the firmware image instance and is only guaranteed to be valid until
 * the next call to 'load'.
 */
struct key_manifest *firmware_imag_eget_key_manifest(struct firmware_image *fw)
{
	ARG_UNUSED(fw);
	return NULL;
}

/**
 * Get the main image header for the current firmware image.
 *
 * @param fw The firmware image to query.
 *
 * @return The image firmware header or null if there is an error.  The memory for the header
 * is managed by the firmware image instance and is only guaranteed to be valid until the next
 * call to 'load'.
 */
struct firmware_header *firmware_image_get_firmware_header(struct firmware_image *fw)
{
	ARG_UNUSED(fw);
	return NULL;
}

void init_update_fw_manifest(struct firmware_image *fw)
{
	// fw->load = firmware_image_load;
	fw->verify = firmware_image_verify;
	// fw->get_image_size = firmware_image_get_image_size;
}
