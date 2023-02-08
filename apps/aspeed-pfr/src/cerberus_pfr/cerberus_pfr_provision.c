/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include <stdint.h>
#include "AspeedStateMachine/common_smc.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "pfr/pfr_ufm.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_key_manifest.h"
#include "include/SmbusMailBoxCom.h"
#include "flash/flash_aspeed.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

uint8_t cRootKeyHash[SHA384_DIGEST_LENGTH] = {0};
uint8_t cPchOffsets[12];
uint8_t cBmcOffsets[12];

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

int cerberus_provisioning_root_key_action(struct pfr_manifest *manifest)
{
	struct PROVISIONING_IMAGE_HEADER provision_header;
	uint16_t modulus_length = 0;
	uint32_t data_length = 0;
	uint32_t region_size = 0;
	CPLD_STATUS cpld_status;
	uint8_t exponent_length;
	int status = Success;

	if (pfr_spi_read(manifest->flash_id, manifest->address, sizeof(provision_header), (uint8_t *)&provision_header)) {
		LOG_ERR("Provisioning: Failed to read image header.");
		return Failure;
	}

	LOG_HEXDUMP_INF(&provision_header, sizeof(provision_header), "Provision Header:");
	status = verify_cerberus_provisioning_type(provision_header.image_type);
	if (status != Success) {
		LOG_ERR("Provisioning: Type Error.");
		return Failure;
	}

	status = verify_rcerberus_magic_number(provision_header.magic_num);
	if (status != Success) {
		LOG_ERR("Provisioning: Magic Number is not Matched.");
		return Failure;
	}

	if (provision_header.provisioning_flag[0] == PROVISION_OTP_KEY_FLAG) {
		//Provision OTP Key Content
		LOG_ERR("Provisioning: Unsupport flag(%d)", provision_header.provisioning_flag[0]);
		return Failure;
	}

	if (provision_header.provisioning_flag[0] == PROVISION_ROOT_KEY_FLAG) {
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_BMC_ACTIVE_OFFSET, 4, cBmcOffsets);
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_BMC_RECOVERY_OFFSET, 4, cBmcOffsets + 4);
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_BMC_STAGE_OFFSET, 4, cBmcOffsets + 8);
		if (ProvisionBmcOffsets(cBmcOffsets, sizeof(cBmcOffsets)) != Success)
			return Failure;

		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_PCH_ACTIVE_OFFSET, 4, cPchOffsets);
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_PCH_RECOVERY_OFFSET, 4, cPchOffsets + 4);
		pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_PCH_STAGE_OFFSET, 4, cPchOffsets + 8);
		if (ProvisionPchOffsets(cPchOffsets, sizeof(cPchOffsets)) != Success)
			return Failure;

		if (cerberus_get_root_key_hash(manifest, manifest->address + CERBERUS_ROOT_KEY_LENGTH,
			PROVISIONING_ROOT_KEY_HASH_TYPE, cRootKeyHash, sizeof(cRootKeyHash)) != Success) {
			LOG_INF("Provisioning: Failed to get root key hash.");
			return Failure;
		}

		if (ProvisionRootKeyHash(cRootKeyHash, sizeof(cRootKeyHash)) != Success)
			return Failure;

		// root key
		// read modulus length
		if (pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_ROOT_KEY_LENGTH, sizeof(modulus_length), (uint8_t *)&modulus_length)) {
			LOG_ERR("Provisioning: Failed to read root key modulus length");
			return Failure;
		}

		if (modulus_length > RSA_MAX_KEY_LENGTH) {
			LOG_ERR("Provisioning: root key modulus length(%d) exceed max length (%d)", modulus_length, RSA_MAX_KEY_LENGTH);
			return Failure;
		}

		// read exponent length
		if (pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_ROOT_KEY + modulus_length, sizeof(exponent_length), &exponent_length)) {
			LOG_ERR("Provisioning: Failed to read root key exponent length");
			return Failure;
		}

		data_length = sizeof(modulus_length) + modulus_length + sizeof(exponent_length) + exponent_length;

		uint8_t key_whole_data[data_length];

		if (pfr_spi_read(manifest->flash_id, manifest->address + CERBERUS_ROOT_KEY_LENGTH, data_length, key_whole_data)) {
			LOG_ERR("Provisioning: Failed to read root key data");
			return Failure;
		}

		// Erasing key manifest data
		region_size = pfr_spi_get_device_size(ROT_INTERNAL_KEY);
		if (pfr_spi_erase_region(ROT_INTERNAL_KEY, true, 0, region_size)) {
			LOG_ERR("Erase the key manifest data failed");
			return Failure;
		}

		if (pfr_spi_write(ROT_INTERNAL_KEY, 0, data_length, key_whole_data)) {
			LOG_ERR("Provisioning: Failed to save root key");
			return Failure;
		}

		ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_status, sizeof(CPLD_STATUS));
		if (cpld_status.DecommissionFlag == TRUE) {
			cpld_status.DecommissionFlag = 0;
			ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_status, sizeof(CPLD_STATUS));
		}

		SetUfmStatusValue(UFM_PROVISIONED);
		LOG_INF("Provisioning: Done.");
	} else
		return Failure;

	return status;
}

