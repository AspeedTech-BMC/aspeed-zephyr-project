/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <logging/log.h>

#include "pfr/pfr_update.h"
#include "pfr/pfr_recovery.h"
#include "pfr/pfr_ufm.h"
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "include/SmbusMailBoxCom.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "cerberus_pfr_common.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_recovery.h"
#include "cerberus_pfr_key_cancellation.h"
#include "flash/flash_aspeed.h"
#include "common/common.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int cerberus_pfr_decommission(struct pfr_manifest *manifest)
{
	CPLD_STATUS cpld_update_status;
	int status = 0;

	if (erase_provision_flash())
		return Failure;

	LOG_INF("Decommission Success");

	memset(&cpld_update_status, 0, sizeof(cpld_update_status));
	cpld_update_status.DecommissionFlag = 1;
	status = ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
	if (status != Success) {
		LOG_ERR("Update ROT status in UPDATE_STATUS_UFM failed");
		return Failure;
	}

	return Success;
}

int cerberus_update_rot_fw(struct pfr_manifest *manifest)
{
	uint32_t region_size = pfr_spi_get_device_size(ROT_INTERNAL_ACTIVE);
	uint32_t source_address = manifest->address;
	uint32_t rot_recovery_address = 0;
	uint32_t rot_active_address = 0;
	uint32_t length_page_align;

	struct recovery_header image_header;
	struct recovery_section image_section;

	pfr_spi_read(manifest->flash_id, source_address, sizeof(image_header),
			(uint8_t *)&image_header);
	source_address = source_address + image_header.header_length;
	pfr_spi_read(manifest->flash_id, source_address, sizeof(image_section),
			(uint8_t *)&image_section);
	source_address = source_address + image_section.header_length;

	length_page_align =
		(image_section.section_length % PAGE_SIZE)
		? (image_section.section_length + (PAGE_SIZE - (image_section.section_length % PAGE_SIZE))) : image_section.section_length;

	if (length_page_align > region_size) {
		LOG_ERR("length(%x) exceed region size(%x)", length_page_align, region_size);
		return Failure;
	}

	if (pfr_spi_erase_region(ROT_INTERNAL_RECOVERY, true, rot_recovery_address,
				region_size)) {
		LOG_ERR("Erase PFR Recovery region failed, address = %x, length = %x",
				rot_recovery_address, region_size);
		return Failure;
	}

	if (pfr_spi_region_read_write_between_spi(ROT_INTERNAL_ACTIVE, rot_active_address,
				ROT_INTERNAL_RECOVERY, rot_recovery_address, region_size)) {
		LOG_ERR("read(ROT_INTERNAL_ACTIVE) address =%x, write(ROT_INTERNAL_RECOVERY) address = %x, length = %x",
				rot_active_address, rot_recovery_address, region_size);
		return Failure;
	}

	if (pfr_spi_erase_region(ROT_INTERNAL_ACTIVE, true, rot_active_address,
				region_size)) {
		LOG_ERR("Erase PFR Active region failed, address = %x, length = %x",
				rot_active_address, region_size);
		return Failure;
	}

	if (pfr_spi_region_read_write_between_spi(BMC_SPI, source_address,
				ROT_INTERNAL_ACTIVE, rot_active_address, length_page_align)) {
		LOG_ERR("read(BMC_SPI) address =%x, write(ROT_INTERNAL_ACTIVE) address = %x, length = %x",
				source_address, rot_active_address, length_page_align);
		return Failure;
	}
	LOG_INF("ROT Firmware update done");

	return Success;
}

int cerberus_hrot_update(struct pfr_manifest *manifest)
{
	int status = 0;
	byte provision_state = GetUfmStatusValue();
	if (provision_state & UFM_PROVISIONED) {
		struct recovery_header image_header;
		pfr_spi_read(manifest->flash_id, manifest->address, sizeof(image_header),
				(uint8_t *)&image_header);
		status =  cerberus_pfr_verify_image(manifest);
		if (status != Success) {
			LOG_ERR("HRoT update pfr verification failed");
			return Failure;
		}

		if (image_header.format == UPDATE_FORMAT_TYPE_HROT) {
			status = cerberus_update_rot_fw(manifest);
			if (status != Success) {
				LOG_ERR("HRoT update failed.");
				return Failure;
			}
		} else if (image_header.format == UPDATE_FORMAT_TYPE_DCC) {
			status = cerberus_pfr_decommission(manifest);
			if (status != Success) {
				LOG_ERR("HRoT decommission failed.");
				return Failure;
			}
		} else if (image_header.format == UPDATE_FORMAT_TYPE_KCC) {
			status = cerberus_pfr_cancel_csk_keys(manifest);
			if (status != Success) {
				LOG_ERR("HRoT cancel CSK keys failed.");
				return Failure;
			}
		} else {
			LOG_HEXDUMP_ERR(&image_header, sizeof(image_header), "Incorrect image header:");
			return Failure;
		}
	} else {
		LOG_INF("Start HROT Provisioning %02x.", provision_state);
		return cerberus_provisioning_root_key_action(manifest);
	}
	return Success;
}

int cerberus_update_recovery_region(int image_type, uint32_t source_address, uint32_t target_address)
{
	return pfr_recover_recovery_region(image_type, source_address, target_address);
}

int cerberus_update_active_region(struct pfr_manifest *manifest, bool erase_rw_regions)
{
	int status = Success;

	struct recovery_header image_header;
	struct recovery_section image_section;

	uint32_t sig_address, recovery_offset, data_offset;
	uint32_t start_address, erase_address, section_length;
	uint32_t region_cnt;
	uint32_t *update_regions = NULL;
	int sector_sz = pfr_spi_get_block_size(manifest->image_type);
	bool support_block_erase = (sector_sz == BLOCK_SIZE);

	//read recovery header
	if (pfr_spi_read(manifest->image_type, manifest->address, sizeof(image_header),
			(uint8_t *)&image_header)) {
		LOG_ERR("Failed to read image header");
		return Failure;
	}

	if (image_header.format != UPDATE_FORMAT_TYPE_BMC &&
	    image_header.format != UPDATE_FORMAT_TYPE_PCH) {
		LOG_ERR("Unsupported image format(%d)", image_header.format);
		return Failure;
	}

	if (!erase_rw_regions) {
		update_regions = cerberus_get_update_regions(manifest, &image_header, &region_cnt);
		if (!update_regions) {
			LOG_ERR("Failed to get update regions from PFM");
			return Failure;
		}
	}

	sig_address = manifest->address + image_header.image_length -
		image_header.sign_length;
	recovery_offset = manifest->address + image_header.header_length;
	bool should_update = false;

	while (recovery_offset < sig_address) {
		status = pfr_spi_read(manifest->image_type, recovery_offset,
				sizeof(image_section), (uint8_t *)&image_section);
		if (image_section.magic_number != RECOVERY_SECTION_MAGIC) {
			status = Failure;
			LOG_ERR("Recovery Section not matched.");
			break;
		}
		start_address = image_section.start_addr;
		section_length = image_section.section_length;
		erase_address = start_address;
		recovery_offset = recovery_offset + sizeof(image_section);
		data_offset = recovery_offset;
		should_update = false;
		recovery_offset = recovery_offset + image_section.section_length;

		if (!erase_rw_regions) {
			for (int i = 0; i < region_cnt; i++) {
				if (erase_address == update_regions[i]) {
					should_update = true;
					break;
				}
			}
		} else {
			should_update = true;
		}

		if (!should_update)
			continue;

		if (pfr_spi_erase_region(manifest->image_type, support_block_erase,
					erase_address, section_length)) {
			status = Failure;
			break;
		}
		if (pfr_spi_region_read_write_between_spi(manifest->image_type, data_offset,
					manifest->image_type, start_address,
					section_length)) {
			status = Failure;
			break;
		}
	}

	if (update_regions)
		free(update_regions);

	return status;
}

int update_firmware_image(uint32_t image_type, void *AoData, void *EventContext)
{
	EVENT_CONTEXT *EventData = (EVENT_CONTEXT *) EventContext;

	uint8_t status = Success;
	uint32_t source_address, target_address, address, act_pfm_offset;
	CPLD_STATUS cpld_update_status;
	uint8_t flash_select = EventData->flash;
	struct pfr_manifest *pfr_manifest = get_pfr_manifest();
	bool erase_rw_regions = false;

	if (((EVENT_CONTEXT *)EventContext)->flag & UPDATE_DYNAMIC)
		erase_rw_regions = true;

	pfr_manifest->state = FIRMWARE_UPDATE;
	pfr_manifest->image_type = image_type;

	LOG_INF("Firmware Update Start.");

	if (pfr_manifest->image_type == BMC_TYPE) {
		// BMC Update/Provisioning
		LOG_INF("BMC Update in Progress");
		if (ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
				sizeof(pfr_manifest->address)))
			return Failure;
		if (ufm_read(PROVISION_UFM, BMC_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	} else if (pfr_manifest->image_type == PCH_TYPE) {
		// PCH Update
		LOG_INF("PCH Update in Progress");
		if (ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
				sizeof(pfr_manifest->address)))
			return Failure;
		if (ufm_read(PROVISION_UFM, PCH_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	} else if (pfr_manifest->image_type == ROT_TYPE) {
		//HROT Update/Decommisioning
		LOG_INF("ROT Update in Progress");
		pfr_manifest->image_type = BMC_TYPE;
		pfr_manifest->address = BMC_CPLD_STAGING_ADDRESS;
		pfr_manifest->flash_id = BMC_FLASH_ID;
		return cerberus_hrot_update(pfr_manifest);
	} else {
		LOG_ERR("Unsupported image type %d", pfr_manifest->image_type);
		return Failure;
	}

	pfr_manifest->staging_address = source_address;
	pfr_manifest->active_pfm_addr = act_pfm_offset;

	status = ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
	if (status != Success)
		return status;
	if (cpld_update_status.BmcToPchStatus == 1) {
		cpld_update_status.BmcToPchStatus = 0;
		status = ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS,
				(uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
		if (status != Success)
			return Failure;

		status = ufm_read(PROVISION_UFM, BMC_STAGING_REGION_OFFSET, (uint8_t *)&address, sizeof(address));
		if (status != Success)
			return Failure;

		address += CONFIG_BMC_STAGING_SIZE;

		// Checking for key cancellation
		pfr_manifest->address = address;

		status = pfr_staging_pch_staging(pfr_manifest);
		if (status != Success)
			return Failure;
	}

	pfr_manifest->image_type = image_type;
	pfr_manifest->address = source_address;

	//BMC/PCH Firmware Update for Active/Recovery Region
	status = pfr_manifest->update_fw->base->verify((struct firmware_image *)pfr_manifest,
			NULL, NULL);
	if (status != Success) {
		LOG_ERR("Staging Area verification failed.");
		if (flash_select == PRIMARY_FLASH_REGION)
			LogUpdateFailure(UPD_CAPSULE_AUTH_FAIL, 1);
		else
			LogUpdateFailure(UPD_CAPSULE_TO_RECOVERY_AUTH_FAIL, 1);

		return Failure;
	}

	if (flash_select == PRIMARY_FLASH_REGION) {
		//Update Active
		LOG_INF("Update Type: Active Update.");
		uint32_t time_start, time_end;

		time_start = k_uptime_get_32();
		status = cerberus_update_active_region(pfr_manifest, erase_rw_regions);
		if (status != Success)
			return Failure;

		time_end = k_uptime_get_32();
		LOG_INF("Firmware update completed, elapsed time = %u milliseconds",
				(time_end - time_start));
	} else {
		//Update Recovery
		LOG_INF("Update Type: Recovery Update.");
		if (image_type == BMC_TYPE) {
			//BMC Update/Provisioning
			get_provision_data_in_flash(BMC_STAGING_REGION_OFFSET, (uint8_t *)&source_address, sizeof(source_address));
			get_provision_data_in_flash(BMC_RECOVERY_REGION_OFFSET, (uint8_t *)&target_address, sizeof(target_address));
		} else if (image_type == PCH_TYPE) {
			//PCH Update
			get_provision_data_in_flash(PCH_STAGING_REGION_OFFSET, (uint8_t *)&source_address, sizeof(source_address));
			get_provision_data_in_flash(PCH_RECOVERY_REGION_OFFSET, (uint8_t *)&target_address, sizeof(target_address));
		}

		status = cerberus_update_recovery_region(image_type, source_address, target_address);
	}
	return status;
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
	ARG_UNUSED(hash);
	ARG_UNUSED(rsa);

	struct pfr_manifest *manifest = (struct pfr_manifest *) fw;

	init_stage_and_recovery_offset(manifest);
	manifest->address = manifest->staging_address;
	return cerberus_pfr_verify_image(manifest);
}

