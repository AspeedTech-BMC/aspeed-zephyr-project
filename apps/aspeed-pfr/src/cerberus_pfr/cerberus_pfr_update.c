/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_CERBERUS_PFR)
#include <logging/log.h>

#include "pfr/pfr_update.h"
#include "pfr/pfr_ufm.h"
#include "StateMachineAction/StateMachineActions.h"
#include "AspeedStateMachine/common_smc.h"
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "pfr/pfr_common.h"
#include "include/SmbusMailBoxCom.h"
#include "StateMachineAction/StateMachineActions.h"
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_recovery.h"
#include "flash/flash_aspeed.h"
#include "common/common.h"
#include "keystore/KeystoreManager.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#define DECOMMISSION_PC_SIZE		128

int cerberus_set_ufm_svn(struct pfr_manifest *manifest, uint8_t ufm_location, uint8_t svn_number)
{
	return Success;
}

int get_ufm_svn(struct pfr_manifest *manifest, uint8_t offset){

	return 0;
}

int cerberus_pfr_decommission(struct pfr_manifest *manifest)
{
	int status = 0;
	uint8_t decom_buffer[DECOMMISSION_PC_SIZE] = {0};
	uint8_t read_buffer[DECOMMISSION_PC_SIZE] = {0};

	CPLD_STATUS cpld_update_status;

	status = pfr_spi_read(manifest->image_type, manifest->address, manifest->pc_length, read_buffer);
	if(status != Success ){
		LOG_ERR("PfrDecommission failed.");
		return Failure;
	}

	status = compare_buffer(read_buffer, decom_buffer, sizeof(read_buffer));
	if(status != Success){
		LOG_ERR("Invalid decommission capsule data.");
		return Failure;
	}

	// Erasing provisioned data
	LOG_INF("Decommission Success.Erasing the provisioned UFM data.");

	status = ufm_erase(PROVISION_UFM);
	if (status != Success)
		return Failure;

	memset(&cpld_update_status,0, sizeof(cpld_update_status));

	cpld_update_status.DecommissionFlag = 1;
	status = ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS,(uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
	if (status != Success)
		return Failure;
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

	pfr_spi_read(manifest->flash_id, source_address, sizeof(image_header), &image_header);
	source_address = source_address + image_header.header_length;
	pfr_spi_read(manifest->flash_id, source_address, sizeof(image_section), &image_section);
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
	if (provision_state & UFM_PROVISIONED){
		struct recovery_header image_header;
		pfr_spi_read(manifest->flash_id, manifest->address, sizeof(image_header), &image_header);
		status =  cerberus_pfr_verify_image(manifest);
		if(status != Success){
			LOG_ERR("HRoT update pfr verification failed");
			return Failure;
		}

		if (image_header.format == ROT_TYPE) {
			status = cerberus_update_rot_fw(manifest);
			if(status != Success){
				LOG_ERR("HRoT update failed.");
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


int cerberus_rot_svn_policy_verify(struct pfr_manifest *manifest, uint32_t hrot_svn)
{
	return Success;
}

int cerberus_keystore_update(struct pfr_manifest *manifest, uint16_t image_format)
{
	int status = 0;
	uint8_t buffer;
	uint16_t header_length;
	uint16_t capsule_type;
	uint16_t section_header_length;
	uint32_t pc_type_status;

	// Get the Header Length
	status = pfr_spi_read(manifest->image_type, manifest->address, sizeof(header_length),
			(uint16_t *)&header_length);
	if(status != Success){
		LOG_ERR("HROT update read header length failed");
		return Failure;
	}

	status = pfr_spi_read(manifest->image_type, manifest->address + header_length,
			sizeof(section_header_length), (uint16_t *)&section_header_length);
	if(status != Success){
		LOG_ERR("HROT update read header failed");
		return Failure;
	}

	if (image_format == KEY_CANCELLATION_TYPE) {
		uint8_t cancelled_key;
		int get_key_id = 0xFF;
		int last_key_id = 0xFF;
		uint8_t pub_key[256];
		struct Keystore_Manager keystore_manager;
		keystoreManager_init(&keystore_manager);

		status = pfr_spi_read(manifest->image_type,
				manifest->address + header_length + section_header_length - 2,
				sizeof(capsule_type), (uint16_t *)&capsule_type);
		manifest->pc_type = capsule_type;
		LOG_INF("capsule_type is %x",capsule_type);
		status = pfr_spi_read(manifest->image_type,
				manifest->address + header_length + section_header_length,
				256, (uint8_t *)&pub_key);
		if(status != Success){
			LOG_ERR("HROT update read signature failed");
			status = Failure;
		}
		status = keystore_get_key_id(&keystore_manager.base, &pub_key, &get_key_id,
				&last_key_id);
		if (get_key_id != 0xFF) {
			if (get_key_id == 0) {
				LOG_ERR("Root Key could not be Cancelled");
			} else {
				status = manifest->keystore->kc_flag->cancel_kc_flag(manifest, get_key_id);
				if(status == Success)
					LOG_INF("Key cancellation success. Key Id :%d was cancelled",get_key_id);
			}
		} else {
			status = KEYSTORE_NO_KEY;
		}
	} else if (image_format == DECOMMISSION_TYPE) {
		status = cerberus_pfr_decommission(manifest);
	}
	return status;
}

int cerberus_check_svn_number(struct pfr_manifest *manifest, uint32_t read_address, uint8_t current_svn_number)
{
	return Success;
}

int cerberus_update_recovery_region(int image_type, uint32_t source_address, uint32_t target_address)
{
	return pfr_recover_recovery_region(image_type, source_address, target_address);
}

uint32_t *cerberus_get_update_regions(struct pfr_manifest *manifest,
		struct recovery_header *image_header, uint32_t *region_cnt)
{
	struct recovery_section image_section;
	struct manifest_header manifest_header;
	bool found_pfm = false;
	uint32_t sig_address = manifest->address + image_header->image_length -
			image_header->sign_length;
	uint32_t read_address = manifest->address + image_header->header_length;
	// Find PFM in update image
	while(read_address < sig_address) {
		if (pfr_spi_read(manifest->image_type, read_address, sizeof(image_section),
					(uint8_t *)&image_section)) {
			LOG_ERR("Failed to read image section info in Flash : %d , Offset : %x",
					manifest->image_type, read_address);
			return NULL;
		}

		if (image_section.magic_number != RECOVERY_SECTION_MAGIC) {
			LOG_ERR("Recovery Section magic number not matched.");
			return NULL;
		}

		read_address = read_address + sizeof(image_section);
		if (pfr_spi_read(manifest->image_type, read_address,
					sizeof(struct manifest_header),
					(uint8_t *)&manifest_header)) {
			LOG_ERR("Failed to read PFM from update image");
			return NULL;
		}

		if ((manifest_header.magic == PFM_V2_MAGIC_NUM) &&
				(manifest_header.sig_length <
				(manifest_header.length - sizeof(manifest_header))) &&
				(manifest_header.sig_length <= RSA_KEY_LENGTH_2K)) {
			found_pfm = true;
			break;
		}

		read_address += image_section.section_length;
	}

	if (!found_pfm) {
		LOG_ERR("PFM doesn't exist in update image");
		return NULL;
	}
	uint32_t pfm_start_addr = image_section.start_addr;

	// Get read only regions from PFM
	read_address += sizeof(manifest_header);
	// Get region counts
	struct manifest_toc_header toc_header;
	if (pfr_spi_read(manifest->image_type, read_address, sizeof(toc_header),
				(uint8_t*)&toc_header)) {
		LOG_ERR("Failed to read toc header");
		return NULL;
	}
	read_address += sizeof(toc_header) +
		(toc_header.entry_count * sizeof(struct manifest_toc_entry)) +
		(toc_header.entry_count * SHA256_HASH_LENGTH) +
		SHA256_HASH_LENGTH;

	// Platform Header Offset
	struct manifest_platform_id plat_id_header;

	if (pfr_spi_read(manifest->image_type, read_address, sizeof(plat_id_header),
				(uint8_t *)&plat_id_header)) {
		LOG_ERR("Failed to read TOC header");
		return NULL;
	}

	// id length should be 4 byte aligned
	uint8_t alignment = (plat_id_header.id_length % 4) ?
		(4 - (plat_id_header.id_length % 4)) : 0;
	uint16_t id_length = plat_id_header.id_length + alignment;
	read_address += sizeof(plat_id_header) + id_length;

	// Flash Device Element Offset
	struct pfm_flash_device_element flash_dev;

	if (pfr_spi_read(manifest->image_type, read_address, sizeof(flash_dev),
				(uint8_t *)&flash_dev)) {
		LOG_ERR("Failed to get flash device element");
		return NULL;
	}

	if (flash_dev.fw_count == 0) {
		LOG_ERR("Unknow firmware");
		return NULL;
	}

	read_address += sizeof(flash_dev);

	// PFM Firmware Element Offset
	struct pfm_firmware_element fw_element;

	if (pfr_spi_read(manifest->image_type, read_address, sizeof(fw_element),
				(uint8_t *)&fw_element)) {
		LOG_ERR("Failed to get PFM firmware element");
		return NULL;
	}

	// id length should be 4 byte aligned
	alignment = (fw_element.id_length % 4) ? (4 - (fw_element.id_length % 4)) : 0;
	id_length = fw_element.id_length + alignment;
	read_address += sizeof(fw_element) - sizeof(fw_element.id) + id_length;

	// PFM Firmware Version Element Offset
	struct pfm_firmware_version_element fw_ver_element;

	if (pfr_spi_read(manifest->image_type, read_address, sizeof(fw_ver_element),
				(uint8_t *)&fw_ver_element)) {
		LOG_ERR("Failed to get PFM firmware version element");
		return NULL;
	}

	// version length should be 4 byte aligned
	alignment = (fw_ver_element.version_length % 4) ?
		(4 - (fw_ver_element.version_length % 4)) : 0;
	uint8_t ver_length = fw_ver_element.version_length + alignment;
	read_address += sizeof(fw_ver_element) - sizeof(fw_ver_element.version) + ver_length;

	// PFM Firmware Version Elenemt RW Region
	read_address += fw_ver_element.rw_count * sizeof(struct pfm_fw_version_element_rw_region);

	// PFM Firmware Version Element Image Offset
	uint8_t *hashStorage = getNewHashStorage();
	uint16_t module_length;
	uint8_t exponent_length;
	uint32_t start_address;
	uint32_t end_address;
	uint32_t *update_regions = malloc(sizeof(uint32_t) * (fw_ver_element.img_count + 1));
	*region_cnt = 0;
	update_regions[*region_cnt] = pfm_start_addr;
	++*region_cnt;

	for (int signed_region_id = 0; signed_region_id < fw_ver_element.img_count;
			signed_region_id++) {
		read_address += sizeof(struct pfm_fw_version_element_image);
		read_address += RSA_KEY_LENGTH_2K;

		// Modulus length of Public Key
		if (pfr_spi_read(manifest->image_type, read_address, sizeof(module_length),
					(uint8_t *)&module_length)) {
			LOG_ERR("Failed to get modulus length");
			return NULL;
		}

		read_address += sizeof(module_length);
		read_address += module_length;

		// Exponent length of Public Key
		if (pfr_spi_read(manifest->image_type, read_address, sizeof(exponent_length),
					(uint8_t *)&exponent_length)) {
			LOG_ERR("Failed to get exponent length");
			return NULL;
		}
		read_address += sizeof(exponent_length);
		read_address += exponent_length;

		// Region Start Address
		pfr_spi_read(manifest->image_type, read_address, sizeof(start_address),
				(uint8_t *)&start_address);
		read_address += sizeof(start_address);

		// Region End Address
		pfr_spi_read(manifest->image_type, read_address, sizeof(end_address),
				(uint8_t *)&end_address);
		read_address += sizeof(end_address);
		update_regions[*region_cnt] = start_address;
		++*region_cnt;
	}

	return update_regions;
}

int cerberus_update_active_region(struct pfr_manifest *manifest, bool erase_rw_regions)
{
	int status = Success;

	struct recovery_header image_header;
	struct recovery_section image_section;

	uint32_t sig_address, recovery_offset, data_offset;
	uint32_t start_address, erase_address, section_length;
	uint32_t target_address;
	uint32_t region_cnt;
	uint32_t *update_regions = NULL;
	uint8_t platform_length;
	int sector_sz = pfr_spi_get_block_size(manifest->image_type);
	bool support_block_erase = (sector_sz == BLOCK_SIZE);

	//read recovery header
	if (pfr_spi_read(manifest->image_type, manifest->address, sizeof(image_header),
			&image_header)) {
		LOG_ERR("Failed to read image header");
		return Failure;
	}
	if (image_header.format == KEY_CANCELLATION_TYPE ||
			image_header.format == DECOMMISSION_TYPE) {
		return cerberus_keystore_update(manifest, image_header.format);
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
	recovery_offset = manifest->address + sizeof(image_header);
	status = pfr_spi_read(manifest->image_type, recovery_offset,
			sizeof(platform_length), &platform_length);
	recovery_offset = recovery_offset + platform_length + 1;
	bool should_update = false;

	while(recovery_offset != sig_address) {
		status = pfr_spi_read(manifest->image_type, recovery_offset,
				sizeof(image_section), &image_section);
		if(image_section.magic_number != RECOVERY_SECTION_MAGIC) {
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

/*
TODO:
After provisioning, need to change the way to get stage offset
*/
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

	// TODO:
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
	} else if(pfr_manifest->image_type == PCH_TYPE) {
		// PCH Update
		LOG_INF("PCH Update in Progress");
		if (ufm_read(PROVISION_UFM, PCH_STAGING_REGION_OFFSET, (uint8_t *)&source_address,
				sizeof(pfr_manifest->address)))
			return Failure;
		if (ufm_read(PROVISION_UFM, PCH_ACTIVE_PFM_OFFSET, (uint8_t *) &act_pfm_offset,
					sizeof(act_pfm_offset)))
			return Failure;
	} else if(pfr_manifest->image_type == ROT_TYPE) {
		//HROT Update/Decommisioning
		LOG_INF("ROT Update in Progress");
		pfr_manifest->image_type = BMC_TYPE;
		pfr_manifest->address = BMC_CPLD_STAGING_ADDRESS;
		pfr_manifest->flash_id = BMC_FLASH_ID;
		return cerberus_hrot_update(pfr_manifest);
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
	status = pfr_manifest->update_fw->base->verify(pfr_manifest, NULL, NULL);
	if (status != Success) {
		LOG_ERR("Staging Area verification failed.");
		LogUpdateFailure(UPD_CAPSULE_AUTH_FAIL, 1);
		return Failure;
	}

	if (flash_select == PRIMARY_FLASH_REGION) {
		//Update Active
		LOG_INF("Update Type: Active Update.");
		status = cerberus_update_active_region(pfr_manifest, erase_rw_regions);
	} else {
		//Update Recovery
		LOG_INF("Update Type: Recovery Update.");
		if (image_type == BMC_TYPE) {
			//BMC Update/Provisioning
			get_provision_data_in_flash(BMC_STAGING_REGION_OFFSET, (uint8_t *)&source_address, sizeof(source_address));
			get_provision_data_in_flash(BMC_RECOVERY_REGION_OFFSET, (uint8_t *)&target_address, sizeof(target_address));
		} else if(image_type == PCH_TYPE) {
			//PCH Update
			get_provision_data_in_flash(PCH_STAGING_REGION_OFFSET, (uint8_t *)&source_address, sizeof(source_address));
			get_provision_data_in_flash(PCH_RECOVERY_REGION_OFFSET, (uint8_t *)&target_address, sizeof(target_address));
		}

		status = cerberus_update_recovery_region(image_type, source_address, target_address);
	}
	return status;
}

void cerberus_watchdog_timer(uint32_t image_type)
{
#if 0
	if (image_type == BMC_TYPE)
		printk("Watchdog timer BMC TYPE\r\n");
	else
		printk("Watchdog timer PCH TYPE\r\n");
#endif
}

int check_staging_area(void)
{

	int status = 0;

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
#endif // CONFIG_CERBERUS_PFR
