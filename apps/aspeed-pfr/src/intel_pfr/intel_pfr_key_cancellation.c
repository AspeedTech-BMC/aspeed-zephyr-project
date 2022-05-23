/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <stdint.h>
#include "intel_pfr_provision.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_verification.h"
#include "flash/flash_wrapper.h"
#include "state_machine/common_smc.h"
#include "flash/flash_aspeed.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include <StateMachineAction/StateMachineActions.h>
#include <gpio/gpio_aspeed.h>
#include <drivers/misc/aspeed/pfr_aspeed.h>

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#undef DEBUG_PRINTF
#if PFR_AUTHENTICATION_DEBUG
#define DEBUG_PRINTF LOG_INF
#else
#define DEBUG_PRINTF(...)
#endif

int get_cancellation_policy_offset(uint32_t pc_type)
{
	if ((pc_type == CPLD_CAPSULE_CANCELLATION) || (pc_type == PFR_CPLD_UPDATE_CAPSULE))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_CPLD_UPDATE_CAPSULE;
	else if ((pc_type == PCH_PFM_CANCELLATION) || (pc_type == PFR_PCH_PFM))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_PCH_PFM;
	else if ((pc_type == PCH_CAPSULE_CANCELLATION) || (pc_type == PFR_PCH_UPDATE_CAPSULE))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_PCH_UPDATE_CAPSULE;
	else if ((pc_type == BMC_PFM_CANCELLATION) || (pc_type == PFR_BMC_PFM))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_BMC_PFM;
	else if ((pc_type == BMC_CAPSULE_CANCELLATION) || (pc_type == PFR_BMC_UPDATE_CAPSULE) || (pc_type == DECOMMISSION_CAPSULE))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_BMC_UPDATE_CAPSULE;

	return 0;
}

int validate_key_cancellation_flag(struct pfr_manifest *manifest)
{

	uint32_t status = 0;
	uint32_t key_id = 0;
	uint32_t block1_address = manifest->address + sizeof(PFR_AUTHENTICATION_BLOCK0);

	if ((manifest->pc_type == CPLD_CAPSULE_CANCELLATION) || (manifest->pc_type == PCH_PFM_CANCELLATION) || (manifest->pc_type == PCH_CAPSULE_CANCELLATION)
	    || (manifest->pc_type == BMC_PFM_CANCELLATION) || (manifest->pc_type == BMC_CAPSULE_CANCELLATION)) {
		manifest->kc_flag = TRUE;
	} else   {
		// Read Csk key ID
		status = pfr_spi_read(manifest->image_type, block1_address + CSK_KEY_ID_ADDRESS, sizeof(key_id), &key_id);
		if (status != Success)
			return Failure;

		status = manifest->keystore->kc_flag->verify_kc_flag(manifest, key_id);
		if (status != Success)
			return Failure;

		manifest->kc_flag = FALSE;
	}

	DEBUG_PRINTF("KeyCancellationFlag : %x ", manifest->kc_flag);

	return Success;
}

int verify_csk_key_id(struct pfr_manifest *manifest, uint32_t key_id)
{

	int status = 0;
	uint32_t ufm_offset = get_cancellation_policy_offset(manifest->pc_type);

	uint8_t old_key_id[CSK_KEY_SIZE] = { 0 };
	uint8_t new_key_id = 1;

	if (manifest->pc_type == PFR_PCH_CPU_Seamless_Update_Capsule)
		return Success;

	if (!ufm_offset)
		return Failure;

	status = ufm_read(PROVISION_UFM, ufm_offset, old_key_id, sizeof(old_key_id));
	if (status != Success)
		return Failure;

	new_key_id = new_key_id << (key_id % 8);
	if ((key_id / 8) > (CSK_KEY_SIZE - 1)) {
		DEBUG_PRINTF("Invalid Key Id");
		return Failure;
	}

	if (!(new_key_id & old_key_id[key_id / 8])) {
		DEBUG_PRINTF("This PFR CSK Key Was cancelled..!Can't Proceed with verify with this key Id: %d", key_id);
		return Failure;
	}

	return Success;

}

int cancel_csk_key_id(struct pfr_manifest *manifest, uint32_t key_id)
{
	uint32_t ufm_offset = get_cancellation_policy_offset(manifest->pc_type);
	uint8_t cancellation_byte_old[16] = { 0 };
	uint8_t cancellation_byte_new = 1;
	uint8_t byte_no = 0;
	uint8_t bit_no = 0;

	int status = 0;

	uint8_t policy_data = 0;

	if (!ufm_offset) {
		DEBUG_PRINTF("Invalid provisioned UFM offset for key cancellation");
		return Failure;
	}

	byte_no = key_id / 8;
	bit_no = key_id % 8;
	ufm_offset = ufm_offset + byte_no;

	// store policy data from flash part
	status = ufm_read(PROVISION_UFM, ufm_offset, &policy_data, 1);
	if (status != Success) {
		DEBUG_PRINTF("ReadCancellationPolicyStatus load cancellation policy fail");
		return Failure;
	}

	policy_data = policy_data & ~(0x01 << bit_no);

	status = ufm_write(PROVISION_UFM, ufm_offset, &policy_data, 1);
	if (status != Success) {
		DEBUG_PRINTF("ReadCancellationPolicyStatus write cancellation policy fail");
		return Failure;
	}

	return Success;

}
