/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>

#include "include/definitions.h"
#include "common/pfm_headers.h"
#include "firmware/app_image.h"
#include "common/common.h"

uint8_t recovery_image_magic_num[4] = {0x8A,0x14,0x7C,0x29};

void recovery_initialize()
{
	initializeEngines();
	initializeManifestProcessor();
}

void recovery_unintialize()
{
	uninitializeEngines();
	uninitializeManifestProcessor();
}

int recovery_header_magic_num_check(uint8_t *magic_num){
	if (memcmp(magic_num, recovery_image_magic_num, sizeof(recovery_image_magic_num))){
		return 0;
	}else{
		printk("Recovery Header Magic Number not Match.\r\n");
		return 1;
	}

}

int recovery_verification(struct flash *flash,struct hash_engine *hash,struct rsa_engine *rsa,
		struct rsa_public_key *pub_key,uint8_t *hash_out,size_t hash_length){
	int status = 0;
	struct recovery_image_header recovery_header;
	uint32_t recovery_signature_offset;
	int signature_length;

	flash->read (flash, RECOVERY_IMAGE_BASE_ADDRESS, &recovery_header,sizeof (recovery_header));

	status = recovery_header_magic_num_check(recovery_header.magic_num);
	// if (status)
	// 	return status;

	signature_length =  *((uint32_t*)  recovery_header.sig_length);
	uint8_t signature[signature_length];

	recovery_signature_offset = RECOVERY_IMAGE_BASE_ADDRESS + *((uint32_t*)  recovery_header.image_length) - *((uint32_t*)  recovery_header.sig_length);

	flash->read (flash, recovery_signature_offset, signature,signature_length);

	status = flash_verify_contents(flash,
			RECOVERY_IMAGE_BASE_ADDRESS,
			*((uint32_t*)  recovery_header.image_length) - *((uint32_t*)  recovery_header.sig_length),
			get_hash_engine_instance(),
			1,
			getRsaEngineInstance(),
			signature,
			256,
			pub_key,
			hash_out,
			256
			);
	return status;
}

int recovery_action(struct flash *flash,uint8_t *recovery_address)
{
	int status = 0;
	struct recovery_image_header recovery_header;
	struct recovery_image recovery_info;
	uint32_t image_offset = 0, recovery_signature_offset, erase_block_offset;
	int match_flag = 0;
	char buf[2048];
	uint32_t recovery_read_offset, active_write_offset;
	int block_count = 0;
	int page_count = 0;
	flash->read (flash, RECOVERY_IMAGE_BASE_ADDRESS, &recovery_header,sizeof (recovery_header));

	image_offset = RECOVERY_IMAGE_BASE_ADDRESS + recovery_header.header_length;
	recovery_signature_offset = RECOVERY_IMAGE_BASE_ADDRESS + *((uint32_t*)  recovery_header.image_length) - *((uint32_t*)  recovery_header.sig_length);

	do{
		flash->read (flash, image_offset, &recovery_info,sizeof (recovery_info));

		image_offset += sizeof(recovery_info); // image data start

		if(!memcmp(recovery_address, recovery_info.address, sizeof(recovery_info.address))){
			printk("Start Recovery\n");

			match_flag = 1;
			//do recovery here;
			recovery_read_offset = image_offset;
			active_write_offset = *((uint32_t*)recovery_address);

			printk("recovery offset:%x\n", active_write_offset);

			page_count = *((uint32_t*)recovery_info.image_length) / sizeof(buf);
			block_count = *((uint32_t*)recovery_info.image_length) / 1024 / 64;

			erase_block_offset = active_write_offset;
			for(int i = 0; i < block_count; i++){
				flash->block_erase(flash, erase_block_offset);
				erase_block_offset += 1024 * 64; // 64K
			}

			for(int page = 0; page < page_count; page++){
				flash->read (flash, recovery_read_offset + page * sizeof(buf), buf,sizeof(buf));
				flash->write(flash, active_write_offset + page * sizeof(buf), buf, sizeof(buf));
			}
			printk("recovery offset:%x recovery successful\n", active_write_offset);
			break;
		}
		image_offset += *((uint32_t*)recovery_info.image_length);// image data end
	}while (image_offset != recovery_signature_offset);

	return status;
}

int performImageRecovery()
{
	int recovery_verify_result = 0;
	int recovery_verify_flag = 0;

	struct manifest_flash *manifest_flash = getManifestFlashInstance();
	struct signature_firmware_region firmware_info;

	if(recovery_verify_flag == 0){
		struct rsa_public_key pub_key;
		uint8_t *hashStorage = getNewHashStorage();

		int status = read_rsa_public_key(&pub_key);
		if(status)
			return status;
		printk("Recovery Verification\n");
		recovery_verify_result = recovery_verification(manifest_flash->flash,
				get_hash_engine_instance(),
				getRsaEngineInstance(),
				&pub_key,
				hashStorage,
				256);
		recovery_verify_flag++;

		if(recovery_verify_result){
			printk("Recovery Verification Fail\n");
			return recovery_verify_result;
		}else{
			printk("Recovery Verification Successful\n");
		}
	}

	return recovery_action(manifest_flash->flash,firmware_info.start_address);
}
