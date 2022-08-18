/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_CERBERUS_PFR)

#include <logging/log.h>

#include "common/common.h"
#include "pfr/pfr_common.h"
#include "pfr/pfr_util.h"
#include "AspeedStateMachine/common_smc.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_provision.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

#ifdef CONFIG_DUAL_SPI
#define DUAL_SPI 1
#else
#define DUAL_SPI 0
#endif

uint8_t pfm_signature_cache[RSA_MAX_KEY_LENGTH]; /**< Buffer for the manifest signature. */
uint8_t pfm_platform_id_cache[256]; /**< Cache for the platform ID. */

int rsa_verify_signature(struct signature_verification *verification,
		const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	struct rsa_engine_wrapper *rsa = getRsaEngineInstance();
	struct rsa_public_key rsa_public;
	int status = Success;

	get_rsa_public_key(ROT_INTERNAL_INTEL_STATE, CERBERUS_ROOT_KEY_ADDRESS, &rsa_public);
	status = rsa->base.sig_verify(&rsa->base, &rsa_public, signature, sig_length, digest, length);
	if (status != Success) {
		LOG_ERR("public mod length = 0x%x", rsa_public.mod_length);
		LOG_ERR("public exponent = 0x%x", rsa_public.exponent);
		LOG_HEXDUMP_ERR(rsa_public.modulus, rsa_public.mod_length, "public modulus:");
		LOG_HEXDUMP_ERR(signature, sig_length, "signature:");
		LOG_HEXDUMP_ERR(digest, length, "expected hash:");
	}

	return status;
}

int signature_verification_init(struct signature_verification *verification)
{
	memset(verification, 0, sizeof(struct signature_verification));
	verification->verify_signature = rsa_verify_signature;

	return Success;
}

int get_rsa_public_key(uint8_t flash_id, uint32_t address, struct rsa_public_key *public_key)
{
	uint32_t exponent_address;
	uint32_t modules_address;
	uint16_t key_length;
	int status = Success;

	//key length
	status = pfr_spi_read(flash_id, address, sizeof(key_length), (uint8_t *)&key_length);
	if (status != Success) {
		LOG_ERR("Flash read rsa key length failed");
		return Failure;
	}

	public_key->mod_length = key_length;
	//rsa key modules
	modules_address = address + sizeof(key_length);
	status = pfr_spi_read(flash_id, modules_address, key_length, public_key->modulus);
	if (status != Success) {
		LOG_ERR("Flash read rsa key modules failed");
		return Failure;
	}

	//rsa key exponent
	exponent_address = address + sizeof(key_length) + key_length;
	status = pfr_spi_read(flash_id, exponent_address, sizeof(public_key->exponent), (uint8_t *)&public_key->exponent);
	public_key->exponent = public_key->exponent >> 8;
	if (status != Success) {
		LOG_ERR("Flash read rsa key exponent failed");
		return Failure;
	}

	return status;
}

int cerberus_pfr_manifest_verify(struct manifest *manifest, struct hash_engine *hash,
		struct signature_verification *verification, uint8_t *hash_out, uint32_t hash_length)
{
	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) manifest;
	struct pfm_flash *pfm_flash = getPfmFlashInstance();
	uint8_t *hashStorage = getNewHashStorage();
	int status = 0;

	status = signature_verification_init(getSignatureVerificationInstance());
	if (status)
		return Failure;

	pfr_manifest->flash->device_id[0] = pfr_manifest->image_type;
	status = pfm_flash_init(pfm_flash, &(pfr_manifest->flash->base), pfr_manifest->hash, pfr_manifest->address,
		pfm_signature_cache, RSA_MAX_KEY_LENGTH, pfm_platform_id_cache, sizeof(pfm_platform_id_cache));
	if (status) {
		LOG_ERR("PFM flash init failed");
		return Failure;
	}

	status = pfm_flash->base.base.verify(&(pfm_flash->base.base), pfr_manifest->hash,
			getSignatureVerificationInstance(), hashStorage, HASH_STORAGE_LENGTH);

	if (true == pfm_flash->base_flash.manifest_valid) {
		LOG_INF("PFM Manifest Verification Successful");
		status = Success;
	} else {
		LOG_ERR("PFM Manifest Verification Failure");
		status = Failure;
	}

	return status;
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

		pfr_spi_read(pfr_manifest->image_type, read_address, exponent_length, &pub_key.exponent);
		read_address += exponent_length;

		pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(start_address), &start_address);
		read_address += sizeof(start_address);
		printk("start_address:%x \r\n", start_address);

		pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(end_address), &end_address);
		read_address += sizeof(end_address);
		printk("end_address:%x \r\n", end_address);

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
			if (status == KEYSTORE_NO_KEY)
				status = keystore_manager.base.save_key(&keystore_manager.base, sig_index + 1, &pub_key.modulus, pub_key.mod_length);
			else
				// if key exist and be cancelled. return false.
				status = pfr_manifest->keystore->kc_flag->verify_kc_flag(pfr_manifest, get_key_id);
		}

		if (status != Success) {
			printk("cerberus_verify_image %d Verification Fail\n", sig_index);
			return Failure;
		} else
			printk("cerberus_verify_image %d Verification Successful\n", sig_index);
	}

	return status;
#endif

	return Success;
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
