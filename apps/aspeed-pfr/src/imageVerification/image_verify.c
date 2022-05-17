/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <common/signature_verification.h>

#include <flash/flash_master.h>
#include "image_verify.h"
#include "common/common.h"
#include "common/pfm_headers.h"

void verify_initialize()
{
	initializeEngines();
	initializeManifestProcessor();
}

void verify_uninitialize()
{
	uninitializeEngines();
	uninitializeManifestProcessor();
}

int read_rsa_public_key(struct rsa_public_key *public_key){
	struct flash *flash_device = getFlashDeviceInstance();
	struct manifest_flash manifestFlash;
	uint32_t public_key_offset,exponent_offset;
	uint16_t module_length;
	uint8_t exponent_length;

	flash_device->read(flash_device, PFM_FLASH_MANIFEST_ADDRESS,&manifestFlash.header,sizeof (manifestFlash.header));
	flash_device->read(flash_device, PFM_FLASH_MANIFEST_ADDRESS+manifestFlash.header.length,&module_length,sizeof (module_length));

	public_key_offset = PFM_FLASH_MANIFEST_ADDRESS + manifestFlash.header.length + sizeof (module_length);
	public_key->mod_length = module_length;

	uint8_t buf[public_key->mod_length];

	flash_device->read(flash_device, public_key_offset ,public_key->modulus, public_key->mod_length);

	exponent_offset = public_key_offset + public_key->mod_length;
	flash_device->read(flash_device, exponent_offset ,&exponent_length,sizeof(exponent_length));
	flash_device->read(flash_device,exponent_offset+sizeof(exponent_length) ,&public_key->exponent,exponent_length);

	return 0;
}

int rsa_verify_signature (struct signature_verification *verification,
		const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	struct rsa_public_key rsa_public;
	read_rsa_public_key(&rsa_public);
	struct rsa_engine_wrapper *rsa = getRsaEngineInstance();

	return rsa->base.sig_verify (&rsa->base, &rsa_public, signature, sig_length, digest, length);
}

int signature_verification_init(struct signature_verification *verification)
{
	int status = 0;
	memset (verification, 0, sizeof (struct signature_verification));

	verification->verify_signature = rsa_verify_signature;

	return status;
}

int perform_image_verification()
{
	int status = 0;
	uint8_t flash_signature[256];
	uint32_t firmware_offset;
	int i;
	struct manifest_toc_entry entry;
	struct manifest_platform_id plat_id_header;
	struct manifest_fw_element_header fw_header;
	struct manifest_fw_elements fw_element;
	struct manifest_flash *manifest_flash = getManifestFlashInstance();

	manifest_flash->toc_hash_length = SHA256_HASH_LENGTH;

	//12 bytes
	firmware_offset = manifest_flash->addr + sizeof (manifest_flash->header);

	// 4 bytes
	manifest_flash->flash->read (manifest_flash->flash, firmware_offset, (uint8_t*) &manifest_flash->toc_header,
			sizeof (manifest_flash->toc_header));
	firmware_offset += sizeof (manifest_flash->toc_header);

	// 8 * 4 bytes
	i = 0;
	do {
		firmware_offset += sizeof (entry);
		i++;
	} while ((i < manifest_flash->toc_header.entry_count));

	// 32 * 4 bytes
	firmware_offset += (manifest_flash->toc_header.hash_count * manifest_flash->toc_hash_length);

	//32 bytes
	firmware_offset += manifest_flash->toc_hash_length;

	manifest_flash->flash->read (manifest_flash->flash, firmware_offset, &plat_id_header,
			sizeof (plat_id_header));

	//4 bytes
	firmware_offset += sizeof (plat_id_header);

	//10 bytes
	firmware_offset += plat_id_header.id_length;

	//alignment 2 bytes
	firmware_offset += 2;

	//flash device 4 bytes
	firmware_offset += sizeof(struct manifest_flash_device);

	manifest_flash->flash->read (manifest_flash->flash, firmware_offset, &fw_header,
			sizeof (fw_header));

	//fw_elements 8 bytes
	firmware_offset += sizeof (fw_header) + fw_header.fw_id_length + sizeof(fw_element.alignment);

	struct allowable_fw allow_firmware;

	manifest_flash->flash->read (manifest_flash->flash, firmware_offset, &allow_firmware,
			sizeof (allow_firmware));


	firmware_offset += sizeof (allow_firmware);

	for(int rw_index = 0; rw_index < allow_firmware.header.rw_count; rw_index++){
		firmware_offset += sizeof(struct allowable_rw_region);
	}

	for(int verify_index=0; verify_index < allow_firmware.header.image_count; verify_index++){
		struct signature_firmware_region firmware_info;
		struct rsa_public_key pub_key;
		uint8_t *hashStorage = getNewHashStorage();

		status = read_rsa_public_key(&pub_key);

		memset(&firmware_info, 0, sizeof(firmware_info));
		manifest_flash->flash->read (manifest_flash->flash, firmware_offset, &firmware_info,sizeof (struct signature_firmware_region));

		status = flash_verify_contents(manifest_flash->flash,
				*((uint32_t*) firmware_info.start_address),
				*((uint32_t*) firmware_info.end_address)-*((uint32_t*) firmware_info.start_address)+sizeof(uint8_t),
				get_hash_engine_instance(),
				1,
				getRsaEngineInstance(),
				firmware_info.signature,
				256,
				&pub_key,
				hashStorage,
				256
				);

		if(status){
			printk("Active Verification Fail\n");
			printk("start_address:%x\n",*((uint32_t*) firmware_info.start_address));
			printk("end_address:%x\n",*((uint32_t*) firmware_info.end_address));
		}else{
			printk("Active Region offset %x verify successful\n", *((uint32_t*) firmware_info.start_address));
		}
		firmware_offset += sizeof (firmware_info);
	}

	return status;
}
