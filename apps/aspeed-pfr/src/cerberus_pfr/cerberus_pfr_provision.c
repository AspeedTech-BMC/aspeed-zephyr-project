/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_CERBERUS_PFR)
#include <logging/log.h>
#include <stdint.h>
#include "AspeedStateMachine/common_smc.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "pfr/pfr_common.h"
#include "cerberus_pfr_definitions.h"
#include "pfr/pfr_util.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_verification.h"
#include "include/SmbusMailBoxCom.h"
#include "flash/flash_aspeed.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

uint8_t cRootKeyHash[SHA384_DIGEST_LENGTH] = {0};
uint8_t cPchOffsets[12];
uint8_t cBmcOffsets[12];

int cerberus_g_provision_data;

int verify_rcerberus_magic_number(uint32_t magic_number)
{
	int status = Success;

	if (magic_number != RECOVERY_HEADER_MAGIC)
		status = Failure;
	return status;
}

int verify_cerberus_provisioning_type(uint16_t image_type)
{
	int status = Success;

	if (image_type != PROVISIONING_IMAGE_TYPE)
		status = Failure;
	return status;
}

unsigned char CerberusProvisionBmcOffsets(void)
{
	uint8_t Status;
	uint32_t UfmStatus;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));
	if (cBmcOffsets == NULL)
		return Failure;

	if (!CheckUfmStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK) && !CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_BMC_OFFSETS_BIT_MASK)) {
		Status = set_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, cBmcOffsets, sizeof(cBmcOffsets));
		if (Status == Success) {
			SetUfmFlashStatus(UfmStatus, UFM_STATUS_PROVISIONED_BMC_OFFSETS_BIT_MASK);
			LOG_INF("BMC offsets provisioned");
			return Success;
		}

		LOG_ERR("BMC offsets provision failed...");
		erase_provision_flash();
		return Failure;
	}

	LOG_INF("%s, Provisioned or UFM Locked", __func__);
	return UnSupported;
}

unsigned char CerberusProvisionPchOffsets(void)
{
	uint8_t Status;
	uint32_t UfmStatus;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));
	if (cPchOffsets == NULL)
		return Failure;

	if (!CheckUfmStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK) && !CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_PCH_OFFSETS_BIT_MASK)) {
		Status = set_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)cPchOffsets, sizeof(cPchOffsets));
		if (Status == Success) {
			LOG_INF("PCH offsets provisioned");
			SetUfmFlashStatus(UfmStatus, UFM_STATUS_PROVISIONED_PCH_OFFSETS_BIT_MASK);
			return Success;
		}

		LOG_ERR("PCH offsets provision failed...");
		erase_provision_flash();
		return Failure;
	}

	LOG_INF("%s, Provisioned or UFM Locked", __func__);
	return UnSupported;
}

unsigned char CerberusProvisionRootKeyHash(void)
{
	uint8_t Status;
	uint32_t UfmStatus;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));
	if (cRootKeyHash == NULL)
		return Failure;

	if (!CheckUfmStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK) && !CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_ROOT_KEY_HASH_BIT_MASK)) {
		Status = set_provision_data_in_flash(ROOT_KEY_HASH, (uint8_t *)cRootKeyHash, SHA256_DIGEST_LENGTH);
		if (Status == Success) {
			LOG_INF("Root key provisioned");
			SetUfmFlashStatus(UfmStatus, UFM_STATUS_PROVISIONED_ROOT_KEY_HASH_BIT_MASK);
			return Success;
		}

		LOG_ERR("Root key provision failed...");
		erase_provision_flash();
		return Failure;
	}

	LOG_INF("%s, Provisioned or UFM Locked", __func__);
	return UnSupported;
}

int getCerberusProvisionData(int offset, uint8_t *data, uint32_t length)
{
	int status = 0;

	status = pfr_spi_read(ROT_INTERNAL_INTEL_STATE, offset, length, data);
	return status;
}

int cerberus_provisioning_root_key_action(struct pfr_manifest *manifest)
{
	int status = Success;

	struct PROVISIONING_IMAGE_HEADER provision_header;

	pfr_spi_read(manifest->flash_id, manifest->address, sizeof(provision_header), (uint8_t *)&provision_header);
	LOG_HEXDUMP_INF(&provision_header, sizeof(provision_header), "Provision Header:");
	LOG_INF("Verify Provisioning Type.");
	status = verify_cerberus_provisioning_type(provision_header.image_type);
	if (status != Success) {
		LOG_ERR("Provisioning Type Error.");
		return Failure;
	}

	LOG_INF("Verify Provisioning Magic Number.");
	status = verify_rcerberus_magic_number(provision_header.magic_num);
	if (status != Success) {
		LOG_ERR("Magic Number is not Matched.");
		return Failure;
	}

	if (provision_header.provisioning_flag[0] == PROVISION_OTP_KEY_FLAG) {
		//Provision OTP Key Content
		LOG_ERR("Unsupport");
		return Failure;
	}

	if (provision_header.provisioning_flag[0] == PROVISION_ROOT_KEY_FLAG) {
		//Provision root Key Content
		LOG_INF("Provisioning ROOT Key.");
		uint16_t key_length = 0;

		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_BMC_ACTIVE_OFFSET, 4, cBmcOffsets);
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_BMC_RECOVERY_OFFSET, 4, cBmcOffsets + 4);
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_BMC_STAGE_OFFSET, 4, cBmcOffsets + 8);
		if (CerberusProvisionBmcOffsets() != Success)
			return Failure;

		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_PCH_ACTIVE_OFFSET, 4, cPchOffsets);
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_PCH_RECOVERY_OFFSET, 4, cPchOffsets + 4);
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_PCH_STAGE_OFFSET, 4, cPchOffsets + 8);
		if (CerberusProvisionPchOffsets() != Success)
			return Failure;

		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_ROOT_KEY_LENGTH, sizeof(key_length), (uint8_t *)&key_length);

		uint8_t cerberus_root_key[key_length];

		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_ROOT_KEY, key_length, cerberus_root_key);

		manifest->pfr_hash->start_address = manifest->address + CERBERUS_ROOT_KEY;
		manifest->pfr_hash->length = key_length;
		manifest->pfr_hash->type = HASH_TYPE_SHA256;
		manifest->base->get_hash((struct manifest *)manifest, manifest->hash, cRootKeyHash, SHA256_DIGEST_LENGTH);
		if (CerberusProvisionRootKeyHash() != Success)
			return Failure;
		//write root key to d0200

		unsigned int data_length = 0;
		uint8_t exponent_length;

		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_ROOT_KEY + key_length, sizeof(exponent_length), &exponent_length);

		data_length = sizeof(key_length) + key_length + sizeof(exponent_length) + exponent_length;

		uint8_t key_whole_data[data_length];

		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_ROOT_KEY_LENGTH, data_length, key_whole_data);
		pfr_spi_write(ROT_INTERNAL_INTEL_STATE, CERBERUS_ROOT_KEY_ADDRESS, data_length, key_whole_data);

		LOG_INF("Provisioning Done.");

	} else
		return Failure;

	return status;
}

// Verify Root Key hash
int cerberus_verify_root_key_hash(struct pfr_manifest *manifest, uint8_t *root_public_key)
{
	return Success;
}

#endif //CONFIG_CERBERUS_PFR
