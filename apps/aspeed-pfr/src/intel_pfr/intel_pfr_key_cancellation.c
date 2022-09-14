/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_INTEL_PFR)
#include <logging/log.h>
#include <shell/shell.h>

#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "pfr/pfr_ufm.h"
#include "intel_pfr_provision.h"
#include "intel_pfr_definitions.h"
#include "intel_pfr_key_cancellation.h"
#include "AspeedStateMachine/common_smc.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int get_cancellation_policy_offset(uint32_t pc_type)
{
	if ((pc_type == CPLD_CAPSULE_CANCELLATION) || (pc_type == PFR_CPLD_UPDATE_CAPSULE) || (pc_type == DECOMMISSION_CAPSULE))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_CPLD_UPDATE_CAPSULE;
	else if ((pc_type == PCH_PFM_CANCELLATION) || (pc_type == PFR_PCH_PFM))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_PCH_PFM;
	else if ((pc_type == PCH_CAPSULE_CANCELLATION) || (pc_type == PFR_PCH_UPDATE_CAPSULE))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_PCH_UPDATE_CAPSULE;
	else if ((pc_type == BMC_PFM_CANCELLATION) || (pc_type == PFR_BMC_PFM))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_BMC_PFM;
	else if ((pc_type == BMC_CAPSULE_CANCELLATION) || (pc_type == PFR_BMC_UPDATE_CAPSULE))
		return KEY_CANCELLATION_POLICY_FOR_SIGNING_BMC_UPDATE_CAPSULE;

	return 0;
}

int validate_key_cancellation_flag(struct pfr_manifest *manifest)
{
	uint32_t block1_address = manifest->address + sizeof(PFR_AUTHENTICATION_BLOCK0);
	uint8_t read_buffer[KCH_CAN_CERT_RESERVED_SIZE] = { 0 };
	uint32_t reserved_address;
	uint32_t status = 0;
	uint32_t key_id = 0;
	int i;

	if ((manifest->pc_type == CPLD_CAPSULE_CANCELLATION) || (manifest->pc_type == PCH_PFM_CANCELLATION)
	    || (manifest->pc_type == PCH_CAPSULE_CANCELLATION) || (manifest->pc_type == BMC_PFM_CANCELLATION)
	    || (manifest->pc_type == BMC_CAPSULE_CANCELLATION)) {
		reserved_address = manifest->address + PFM_SIG_BLOCK_SIZE + 4;
		status = pfr_spi_read(manifest->image_type, reserved_address, sizeof(read_buffer), (uint8_t *)read_buffer);
		if (status != Success) {
			LOG_ERR("Flash read reserved data failed for key cancellation capsule");
			return Failure;
		}

		for (i = 0; i < sizeof(read_buffer); i++) {
			if (read_buffer[i] != 0) {
				LOG_ERR("Invalid reserved data for key cancellation capsule");
				return Failure;
			}
		}

		manifest->kc_flag = TRUE;
	} else   {
		// Read Csk key ID
		status = pfr_spi_read(manifest->image_type, block1_address + CSK_KEY_ID_ADDRESS, sizeof(key_id), (uint8_t *)&key_id);
		if (status != Success) {
			LOG_ERR("Flash read block1 CSK key Id failed");
			return Failure;
		}

		status = manifest->keystore->kc_flag->verify_kc_flag(manifest, key_id);
		if (status != Success)
			return Failure;

		manifest->kc_flag = FALSE;
	}

	LOG_INF("KeyCancellationFlag: %x", manifest->kc_flag);

	return Success;
}

int verify_csk_key_id(struct pfr_manifest *manifest, uint8_t key_id)
{
	uint32_t ufm_offset = get_cancellation_policy_offset(manifest->pc_type);
	uint32_t policy_data;
	uint32_t bit_offset;
	int status = 0;

#if defined(CONFIG_SEAMLESS_UPDATE)
	if (manifest->pc_type == PFR_PCH_SEAMLESS_UPDATE_CAPSULE)
		return Success;
#endif

	if (!ufm_offset) {
		LOG_ERR("%s: Invalid provisioned UFM offset for key cancellation", __func__);
		return Failure;
	}

	// key id must be within 0-127
	if (key_id > KEY_CANCELLATION_MAX_KEY_ID) {
		LOG_ERR("%s: Invalid key Id: %d", __func__, key_id);
		return Failure;
	}

	ufm_offset += (key_id / 32) * 4;
	// bit little endian
	bit_offset = 31 - (key_id % 32);

	status = ufm_read(PROVISION_UFM, ufm_offset, (uint8_t *)&policy_data, sizeof(policy_data));
	if (status != Success) {
		LOG_ERR("%s: Read cancellation policy status from UFM failed", __func__);
		return Failure;
	}

	if (!(policy_data & (0x01 << bit_offset))) {
		LOG_ERR("This CSK key was cancelled..! Can't Proceed with verify with this key Id: %d", key_id);
		return Failure;
	}

	return Success;
}

int cancel_csk_key_id(struct pfr_manifest *manifest, uint32_t key_id)
{
	uint32_t ufm_offset = get_cancellation_policy_offset(manifest->pc_type);
	uint32_t policy_data;
	uint32_t bit_offset;
	int status = 0;

	if (!ufm_offset) {
		LOG_ERR("%s: Invalid provisioned UFM offset for key cancellation", __func__);
		return Failure;
	}

	// key id must be within 0-127
	if (key_id > KEY_CANCELLATION_MAX_KEY_ID) {
		LOG_ERR("%s: Invalid key Id: %d", __func__, key_id);
		return Failure;
	}

	ufm_offset += (key_id / 32) * 4;
	// bit little endian
	bit_offset = 31 - (key_id % 32);

	// store policy data from flash part
	status = ufm_read(PROVISION_UFM, ufm_offset, (uint8_t *)&policy_data, sizeof(policy_data));
	if (status != Success) {
		LOG_ERR("%s: Read cancellation policy status from UFM failed", __func__);
		return Failure;
	}

	policy_data &= ~(0x01 << bit_offset);

	status = ufm_write(PROVISION_UFM, ufm_offset, (uint8_t *)&policy_data, sizeof(policy_data));
	if (status != Success) {
		LOG_ERR("Write cancellation policy status to UFM failed, offset = %x, data = %x", ufm_offset, policy_data);
		return Failure;
	}

	return Success;
}

#ifdef CONFIG_SHELL
static int cmd_cancel_csk_key_id(const struct shell *shell, size_t argc, char **argv)
{
	struct pfr_manifest test_manifest;
	uint32_t key_id;

	test_manifest.pc_type = strtoul(argv[1], NULL, 16);
	key_id = strtoul(argv[2], NULL, 10);

	cancel_csk_key_id(&test_manifest, key_id);

	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	return 0;
}

static int cmd_verify_csk_key_id(const struct shell *shell, size_t argc, char **argv)
{
	struct pfr_manifest test_manifest;
	uint32_t key_id;

	test_manifest.pc_type = strtoul(argv[1], NULL, 16);
	key_id = strtoul(argv[2], NULL, 10);

	if (!verify_csk_key_id(&test_manifest, key_id))
		LOG_INF("This CSK key is not cancelled.., PC type = 0x%x, Key Id = %d", test_manifest.pc_type, key_id);

	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	return 0;
}

static int cmd_dump_key_cancellation_policy(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t buffer[4] = { 0 };
	uint32_t offset = 0;
	uint32_t pc_type;

	pc_type = strtoul(argv[1], NULL, 16);
	offset = get_cancellation_policy_offset(pc_type);

	if (!offset) {
		LOG_ERR("%s: Invalid provisioned UFM offset for key cancellation", __func__);
		return Failure;
	}

	LOG_INF("UFM Offeset = %x", offset);
	ufm_read(PROVISION_UFM, offset, (uint8_t *)buffer, sizeof(buffer));
	LOG_HEXDUMP_INF(buffer, sizeof(buffer), "Key Cancellation Policy");

	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_kc_cmds,
	SHELL_CMD_ARG(verify, NULL, "<pc_type> <key_id>", cmd_verify_csk_key_id, 3, 0),
	SHELL_CMD_ARG(cancel, NULL, "<pc_type> <key_id>", cmd_cancel_csk_key_id, 3, 0),
	SHELL_CMD_ARG(dump, NULL, "<pc_type>", cmd_dump_key_cancellation_policy, 2, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(kc, &sub_kc_cmds, "Key Cancellation Commands", NULL);

#endif

#endif // CONFIG_INTEL_PFR
