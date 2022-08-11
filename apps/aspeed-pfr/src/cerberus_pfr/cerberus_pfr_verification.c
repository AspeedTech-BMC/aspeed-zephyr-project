/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_CERBERUS_PFR)
#include <stdint.h>
#include "AspeedStateMachine/common_smc.h"
#include "pfr/pfr_common.h"
#include "include/definitions.h"
#include "pfr/pfr_util.h"
#include "cerberus_pfr_definitions.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_key_cancellation.h"
#include "cerberus_pfr_verification.h"
#include "common/common.h"
#include "flash/flash_store.h"
#include "keystore/keystore_flash.h"
#include <crypto/rsa.h>
#include <flash/flash_aspeed.h>
#include "engineManager/engine_manager.h"

#undef DEBUG_PRINTF
#if PFR_AUTHENTICATION_DEBUG
#define DEBUG_PRINTF printk
#else
#define DEBUG_PRINTF(...)
#endif

#ifdef CONFIG_DUAL_SPI
#define DUAL_SPI 1
#else
#define DUAL_SPI 0
#endif

int rsa_verify_signature(struct signature_verification *verification,
		const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	struct rsa_public_key rsa_public;

	get_rsa_public_key(ROT_INTERNAL_INTEL_STATE, CERBERUS_ROOT_KEY_ADDRESS, &rsa_public);
	struct rsa_engine *rsa = getRsaEngineInstance();

	return rsa->sig_verify(&rsa, &rsa_public, signature, sig_length, digest, length);
}

int signature_verification_init(struct signature_verification *verification)
{
	int status = 0;

	memset(verification, 0, sizeof(struct signature_verification));

	verification->verify_signature = rsa_verify_signature;

	return status;
}

int get_rsa_public_key(uint8_t flash_id, uint32_t address, struct rsa_public_key *public_key)
{
	int status = Success;
	uint16_t key_length;
	uint8_t exponent_length;
	uint32_t modules_address,exponent_address;
	//Key Length
	status = pfr_spi_read(flash_id, address, sizeof(key_length), &key_length);
	if (status != Success){
		return Failure;
	}

	modules_address = address + sizeof(key_length);
	//rsa_key_module
	status = pfr_spi_read(flash_id, modules_address, key_length, public_key->modulus);

	public_key->mod_length = key_length;
	exponent_address = address + sizeof(key_length) + key_length;

	//rsa_key_exponent
	status = pfr_spi_read(flash_id, exponent_address + 1, sizeof(public_key->exponent) - 1, &public_key->exponent);

	return status;
}

int cerberus_pfr_manifest_verify(struct manifest *manifest, struct hash_engine *hash,
		struct signature_verification *verification, uint8_t *hash_out, uint32_t hash_length)
{
	int status = 0;
	uint8_t *hashStorage = getNewHashStorage();
	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) manifest;
	struct manifest_flash *manifest_flash = getManifestFlashInstance();
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	status = signature_verification_init(getSignatureVerificationInstance());
	if(status){
		return Failure;
	}

	spi_flash->spi.device_id[0] = pfr_manifest->image_type;
	manifest_flash->flash = &spi_flash->spi.base;
	status = manifest_flash_verify(manifest_flash, get_hash_engine_instance(),
			getSignatureVerificationInstance(), hashStorage, HASH_STORAGE_LENGTH);

	if (true == manifest_flash->manifest_valid) {
		printk("Manifest Verification Successful\n");
		status = Success;
	}
	else {
		printk("Manifest Verification Failure \n");
		status = Failure;
	}
	return status;
}

int cerberus_read_public_key(struct rsa_public_key *public_key)
{
	struct flash *flash_device = getFlashDeviceInstance();
	struct manifest_flash manifestFlash;
	uint32_t public_key_offset, exponent_offset;
	uint16_t module_length;
	uint8_t exponent_length;

	pfr_spi_read(0,PFM_FLASH_MANIFEST_ADDRESS, sizeof(manifestFlash.header), &manifestFlash.header);
	pfr_spi_read(0,PFM_FLASH_MANIFEST_ADDRESS + manifestFlash.header.length, sizeof(module_length), &module_length);
	public_key_offset = PFM_FLASH_MANIFEST_ADDRESS + manifestFlash.header.length + sizeof(module_length);
	public_key->mod_length = module_length;

	pfr_spi_read(0,public_key_offset, public_key->mod_length, public_key->modulus);
	exponent_offset = public_key_offset + public_key->mod_length;
	pfr_spi_read(0,exponent_offset, sizeof(exponent_length), &exponent_length);
	int int_exp_length = (int) exponent_length;
	pfr_spi_read(0,exponent_offset + sizeof(exponent_length), int_exp_length, &public_key->exponent);

	return 0;
}


int cerberus_verify_signature(struct signature_verification *verification,
		const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	struct rsa_public_key rsa_public;
	cerberus_read_public_key(&rsa_public);
	struct rsa_engine *rsa = getRsaEngineInstance();
	return rsa->sig_verify(&rsa, &rsa_public, signature, sig_length, digest, length);
}

int cerberus_verify_regions(struct manifest *manifest)
{
#if 0
	int status = 0;
	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) manifest;
	uint8_t platfprm_id_length, fw_id_length;
	uint32_t read_address = pfr_manifest->address;
	uint8_t fw_element_header[4], fw_list_header[4];
	uint8_t sign_image_count, rw_image_count, fw_version_length;
	uint8_t signature[HASH_STORAGE_LENGTH];
	uint16_t module_length;
	struct rsa_public_key pub_key;
	uint8_t exponent_length;
	uint32_t start_address;
	uint32_t end_address;
	uint8_t *hashStorage = getNewHashStorage();
	struct CERBERUS_PFM_RW_REGION rw_region_data;
	struct CERBERUS_SIGN_IMAGE_HEADER sign_region_header;
	status = pfr_spi_read(pfr_manifest->image_type, read_address + CERBERUS_PLATFORM_HEADER_OFFSET, sizeof(platfprm_id_length), &platfprm_id_length);
	printk("Platform ID Length: %x\r\n", platfprm_id_length);

	read_address +=  CERBERUS_PLATFORM_HEADER_OFFSET + PLATFORM_ID_HEADER_LENGTH + platfprm_id_length + 2; //2 byte alignment
	read_address += CERBERUS_FLASH_DEVICE_OFFSET_LENGTH;

	status = pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(fw_element_header), fw_element_header);
	fw_id_length = fw_element_header[1];
	read_address += sizeof(fw_element_header) + fw_id_length + 1; // 1 byte alignment

	//fw_list
	status = pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(fw_list_header), fw_list_header);
	sign_image_count = fw_list_header[0];
	rw_image_count = fw_list_header[1];
	fw_version_length = fw_list_header[2];

	read_address += sizeof(fw_list_header) + CERRBERUS_FW_VERSION_ADDR_LENGTH + fw_version_length + 2; // 2 byte alignment
	read_address += rw_image_count * sizeof(rw_region_data);

	struct Keystore_Manager keystore_manager;

	keystoreManager_init(&keystore_manager);

	for (int sig_index = 0; sig_index < sign_image_count ; sig_index++) {
		read_address += sizeof(sign_region_header);
		pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(signature), signature);
		read_address += sizeof(signature);


		pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(module_length), &module_length);

		pub_key.mod_length = module_length;
		read_address += sizeof(module_length);

		pfr_spi_read(pfr_manifest->image_type, read_address, module_length, pub_key.modulus);
		read_address += module_length;


		pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(exponent_length), &exponent_length);
		read_address += sizeof(exponent_length);

		pfr_spi_read(pfr_manifest->image_type, read_address,exponent_length, &pub_key.exponent);
		read_address += exponent_length;

		pfr_spi_read(pfr_manifest->image_type, read_address,sizeof(start_address), &start_address);
		read_address += sizeof(start_address);
		printk("start_address:%x \r\n",start_address);

		pfr_spi_read(pfr_manifest->image_type, read_address,sizeof(end_address), &end_address);
		read_address += sizeof(end_address);
		printk("end_address:%x \r\n",end_address);

		pfr_manifest->flash->device_id[0] = pfr_manifest->flash_id;	  // device_id will be changed by save_key function
		status = flash_verify_contents((struct flash *)pfr_manifest->flash,
				start_address,
				end_address - start_address + sizeof(uint8_t),
				get_hash_engine_instance(),
				HASH_TYPE_SHA256,
				getRsaEngineInstance(),
				signature,
				256,
				&pub_key,
				hashStorage,
				256
				);
		if (status == Success) {
			int get_key_id = 0xFF;
			int last_key_id = 0xFF;

			status = keystore_get_key_id(&keystore_manager.base, &pub_key.modulus, &get_key_id, &last_key_id);
			if (status == KEYSTORE_NO_KEY) {
				status = keystore_manager.base.save_key(&keystore_manager.base, sig_index + 1 , &pub_key.modulus, pub_key.mod_length);
			} else {
				// if key exist and be cancelled. return false.
				status = pfr_manifest->keystore->kc_flag->verify_kc_flag(pfr_manifest, get_key_id);
			}
		}


		if (status != Success) {
			printk("cerberus_verify_image %d Verification Fail\n", sig_index);
			return Failure;
		} else {
			printk("cerberus_verify_image %d Verification Successful\n", sig_index);
		}

	}

	return status;
#endif
	return Success;
}

void cerberus_init_pfr_authentication(struct pfr_authentication *pfr_authentication)
{
	pfr_authentication->verify_pfm_signature = cerberus_verify_signature;
	pfr_authentication->verify_regions = cerberus_verify_regions;
}

/**
 * Verify if the manifest is valid.
 *
 * @param manifest The manifest to validate.
 * @param hash The hash engine to use for validation.
 * @param verification Verification instance to use to verify the manifest signature.
 * @param hash_out Optional output buffer for manifest hash calculated during verification.  A
 * validation error does not necessarily mean the hash output is not valid.  If the manifest
 * hash was not calculated, this buffer will be cleared.  Set this to null to not return the
 * manifest hash.
 * @param hash_length Length of the hash output buffer.
 *
 * @return 0 if the manifest is valid or an error code.
 */
int manifest_verify(struct manifest *manifest, struct hash_engine *hash,
		struct signature_verification *verification, uint8_t *hash_out,
		size_t hash_length)
{
	return cerberus_pfr_manifest_verify(manifest, hash, verification, hash_out, hash_length);
}

#endif // CONFIG_CERBERUS_PFR
