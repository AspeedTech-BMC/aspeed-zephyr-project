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
#include "AspeedStateMachine/AspeedStateMachine.h"
#include "AspeedStateMachine/common_smc.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "cerberus_pfr_verification.h"
#include "cerberus_pfr_provision.h"
#include "cerberus_pfr_recovery.h"
#include "keystore/KeystoreManager.h"
#include "manifest/manifest_format.h"
#include "manifest/pfm/pfm_format.h"
#include "crypto/rsa.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

int get_signature(uint8_t flash_id, uint32_t address, uint8_t *signature, size_t signature_length)
{
	int status = Success;
	status = pfr_spi_read(flash_id, address, signature_length, signature);

	return status;
}

int verify_recovery_header_magic_number(struct recovery_header rec_head)
{
	int status = Success;
	if (rec_head.format == KEY_CANCELLATION_TYPE || rec_head.format == DECOMMISSION_TYPE) {
		if (rec_head.magic_number != CANCELLATION_HEADER_MAGIC) {
			status = Failure;
		}
	} else {
		if(rec_head.magic_number != RECOVERY_HEADER_MAGIC)
			status = Failure;
	}
	return status;

}

void init_stage_and_recovery_offset(struct pfr_manifest *pfr_manifest)
{
	if(pfr_manifest->image_type == BMC_TYPE) {
		get_provision_data_in_flash(BMC_STAGING_REGION_OFFSET,
				(uint8_t *)&pfr_manifest->staging_address, sizeof(pfr_manifest->address));
		get_provision_data_in_flash(BMC_RECOVERY_REGION_OFFSET,
				(uint8_t *)&pfr_manifest->recovery_address,
				sizeof(pfr_manifest->recovery_address));
		pfr_manifest->flash_id = BMC_FLASH_ID;
	}else if(pfr_manifest->image_type == PCH_TYPE){
		get_provision_data_in_flash(PCH_STAGING_REGION_OFFSET,
				(uint8_t *)&pfr_manifest->staging_address, sizeof(pfr_manifest->address));
		get_provision_data_in_flash(PCH_RECOVERY_REGION_OFFSET,
				(uint8_t *)&pfr_manifest->recovery_address,
				sizeof(pfr_manifest->recovery_address));
		pfr_manifest->flash_id = PCH_FLASH_ID;
	}
}

int cerberus_pfr_verify_image(struct pfr_manifest *manifest)
{
	int status = Success;
	struct recovery_header image_header;
	struct rsa_public_key public_key;

	uint32_t signature_address;
	uint32_t verify_addr = manifest->address;
	uint8_t sig_data[SHA256_SIGNATURE_LENGTH];
	uint8_t *hashStorage = NULL;

	LOG_INF("manifest->flash_id=%d verify address=%x", manifest->flash_id, verify_addr);
	pfr_spi_read(manifest->flash_id, verify_addr, sizeof(image_header), (uint8_t *)&image_header);

	status = verify_recovery_header_magic_number(image_header);
	if (status != Success){
		LOG_HEXDUMP_ERR(&image_header, sizeof(image_header), "image_header:");
		LOG_ERR("Image Header Magic Number is not Matched.");
		return Failure;
	}
	// get public key and init signature
	status = get_rsa_public_key(ROT_INTERNAL_INTEL_STATE, CERBERUS_ROOT_KEY_ADDRESS, &public_key);
	LOG_INF("Public Key Exponent=%08x", public_key.exponent);
	LOG_HEXDUMP_INF(public_key.modulus, public_key.mod_length, "Public Key Modulus:");

	if (status != Success){
		LOG_ERR("Unable to get public Key.");
		return Failure;
	}

	// get signature
	signature_address = verify_addr + image_header.image_length - image_header.sign_length;
	LOG_INF("signature_address=%x", signature_address);
	LOG_INF("image_header.image_length=%x", image_header.image_length);
	LOG_INF("image_header.sign_length=%x", image_header.sign_length);
	status = get_signature(manifest->flash_id, signature_address, sig_data,
			SHA256_SIGNATURE_LENGTH);
	if (status != Success){
		LOG_ERR("Unable to get the Signature.");
		return Failure;
	}

	// verify
	manifest->flash->device_id[0] = manifest->flash_id;
	LOG_HEXDUMP_INF(sig_data, SHA256_SIGNATURE_LENGTH, "Image Signature:");
	status = flash_verify_contents( (struct flash *)manifest->flash,
			verify_addr,
			(image_header.image_length - image_header.sign_length),
			get_hash_engine_instance(),
			HASH_TYPE_SHA256,
			&getRsaEngineInstance()->base,
			sig_data,
			SHA256_SIGNATURE_LENGTH,
			&public_key,
			hashStorage,
			SHA256_SIGNATURE_LENGTH
			);
	if (status != Success){
		LOG_ERR("Image verify Fail manifest->flash_id=%d address=%x", manifest->flash_id,
				verify_addr);
		return Failure;
	}

	LOG_INF("%s Image Verify Success.",
			(manifest->state == FIRMWARE_UPDATE) ? "Stage" : "Recovery");

	return Success;
}

int rsa_verify_signature(struct signature_verification *verification,
		const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	struct rsa_engine_wrapper *rsa = getRsaEngineInstance();
	struct rsa_public_key rsa_public;
	int status = Success;

	get_rsa_public_key(ROT_INTERNAL_INTEL_STATE, CERBERUS_ROOT_KEY_ADDRESS, &rsa_public);
	status = rsa->base.sig_verify(&rsa->base, &rsa_public, signature, sig_length, digest, length);
	if (status != Success) {
		LOG_ERR("public key mod length = 0x%x", rsa_public.mod_length);
		LOG_ERR("public key exponent = 0x%x", rsa_public.exponent);
		LOG_HEXDUMP_ERR(rsa_public.modulus, rsa_public.mod_length, "public key modulus:");
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
	status = pfr_spi_read(flash_id, modules_address, key_length, (uint8_t *)public_key->modulus);
	if (status != Success) {
		LOG_ERR("Flash read rsa key modules failed");
		return Failure;
	}

	//rsa key exponent
	exponent_address = address + sizeof(key_length) + key_length;
	status = pfr_spi_read(flash_id, exponent_address, sizeof(public_key->exponent),
			(uint8_t *)&public_key->exponent);
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
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();
	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) manifest;
	struct manifest_flash *manifest_flash = getManifestFlashInstance();
	struct manifest_toc_header *toc_header = &manifest_flash->toc_header;
	uint32_t read_address;
	int status = 0;
	status = signature_verification_init(getSignatureVerificationInstance());
	if (status)
		return Failure;

	if (pfr_manifest->image_type == BMC_SPI)
		get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));
	else
		get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)&read_address,
				sizeof(read_address));

	spi_flash->spi.device_id[0] = pfr_manifest->image_type;
	status = manifest_flash_init(manifest_flash, getFlashDeviceInstance(), read_address,
			PFM_V2_MAGIC_NUM);
	if (status) {
		LOG_ERR("manifest flash init failed");
		goto free_manifest;
	}

	// TOC header Offset
	read_address = pfr_manifest->address + sizeof(struct manifest_header);
	if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(struct manifest_toc_header),
			(uint8_t *)toc_header)) {
		LOG_ERR("Failed to read TOC header");
		status = Failure;
		goto free_manifest;
	}

	switch (manifest_flash->toc_header.hash_type) {
	case MANIFEST_HASH_SHA256:
		manifest_flash->toc_hash_type = HASH_TYPE_SHA256;
		manifest_flash->toc_hash_length = SHA256_HASH_LENGTH;
		break;
	// Cerberus manifest v1 only support SHA256
	case MANIFEST_HASH_SHA384:
	case MANIFEST_HASH_SHA512:
	default:
		LOG_ERR("Invalid or unsupported hash type");
		status = Failure;
		goto free_manifest;
	}

	uint8_t *hashStorage = getNewHashStorage();
	status = manifest_flash_verify(manifest_flash, get_hash_engine_instance(),
			getSignatureVerificationInstance(), hashStorage,
			manifest_flash->max_signature);

	if (true == manifest_flash->manifest_valid) {
		LOG_INF("Manifest Verification Successful");
		status = Success;
	} else {
		LOG_ERR("Manifest Verification Failure");
		status = Failure;
	}

free_manifest:
	manifest_flash_release(manifest_flash);

	return status;
}

/*
 * Aspeed Cerberus PFM format:
 *
 * struct {
 *     struct manifest_header
 *     struct manifest_toc_header
 *     struct manifest_toc_entry[toc_entry_count]
 *     u8 toc_entry_hash[toc_entry_count][HASH_LEN]
 *     u8 toc_hash[HASH_LEN]
 *     struct manifest_platform_id
 *     struct pfm_flash_device_element
 *     struct pfm_firmware_element
 *     struct pfm_firmware_version_element
 *     struct pfm_fw_version_element_rw_region
 *     struct pfm_fw_version_element_image
 *     struct signed_region_def {
 *         struct pfm_fw_version_element_image
 *         u8 signature[256]
 *         u16 modulus_length
 *         u8 modulus[modulus_length]
 *         u8 exponent_length
 *         u8 exponent[exponent_length]
 *         u32 region_start_addr
 *         u32 region_end_addr
 *     } signed_region[pfm_firmware_version_element.img_count]
 * }
 *
 */
int cerberus_verify_regions(struct manifest *manifest)
{
	struct pfr_manifest *pfr_manifest = (struct pfr_manifest *) manifest;
	struct manifest_flash *manifest_flash = getManifestFlashInstance();
	struct manifest_toc_header *toc_header = &manifest_flash->toc_header;
	uint8_t signature[RSA_MAX_KEY_LENGTH];
	uint32_t read_address;

	// Manifest Header + TOC Header + TOC Entries + TOC Entries Hash + TOC Hash
	read_address = pfr_manifest->address + sizeof(struct manifest_header) +
		sizeof(struct manifest_toc_header) +
		(toc_header->entry_count * sizeof(struct manifest_toc_entry)) +
		(toc_header->entry_count * manifest_flash->toc_hash_length) +
		manifest_flash->toc_hash_length;

	// Platform Header Offset
	struct manifest_platform_id plat_id_header;

	if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(plat_id_header),
			(uint8_t *)&plat_id_header)) {
		LOG_ERR("Failed to read TOC header");
		return Failure;
	}

	// id length should be 4 byte aligned
	uint8_t alignment = (plat_id_header.id_length % 4) ?
		(4 - (plat_id_header.id_length % 4)) : 0;
	uint16_t id_length = plat_id_header.id_length + alignment;
	read_address += sizeof(plat_id_header) + id_length;

	// Flash Device Element Offset
	struct pfm_flash_device_element flash_dev;

	if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(flash_dev),
			(uint8_t *)&flash_dev)) {
		LOG_ERR("Failed to get flash device element");
		return Failure;
	}

	if (flash_dev.fw_count == 0) {
		LOG_ERR("Unknow firmware");
		return Failure;
	}

	read_address += sizeof(flash_dev);

	// PFM Firmware Element Offset
	struct pfm_firmware_element fw_element;

	if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(fw_element),
			(uint8_t *)&fw_element)) {
		LOG_ERR("Failed to get PFM firmware element");
		return Failure;
	}

	// id length should be 4 byte aligned
	alignment = (fw_element.id_length % 4) ? (4 - (fw_element.id_length % 4)) : 0;
	id_length = fw_element.id_length + alignment;
	read_address += sizeof(fw_element) - sizeof(fw_element.id) + id_length;

	// PFM Firmware Version Element Offset
	struct pfm_firmware_version_element fw_ver_element;

	if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(fw_ver_element),
			(uint8_t *)&fw_ver_element)) {
		LOG_ERR("Failed to get PFM firmware version element");
		return Failure;
	}

	// version length should be 4 byte aligned
	alignment = (fw_ver_element.version_length % 4) ?
		(4 - (fw_ver_element.version_length % 4)) : 0;
	uint8_t ver_length = fw_ver_element.version_length + alignment;
	read_address += sizeof(fw_ver_element) - sizeof(fw_ver_element.version) + ver_length;

	// PFM Firmware Version Elenemt RW Region
	read_address += fw_ver_element.rw_count * sizeof(struct pfm_fw_version_element_rw_region);

	// PFM Firmware Version Element Image Offset
	struct pfm_fw_version_element_image fw_ver_element_img;
	uint8_t *hashStorage = getNewHashStorage();
	struct rsa_public_key pub_key;
	uint16_t module_length;
	uint8_t exponent_length;
	uint32_t start_address;
	uint32_t end_address;

	for (int signed_region_id = 0; signed_region_id < fw_ver_element.img_count;
			signed_region_id++) {
		if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(fw_ver_element_img),
					(uint8_t *)&fw_ver_element_img)) {
			LOG_ERR("Failed to get PFM firmware version element image header");
			return Failure;
		}

		read_address += sizeof(fw_ver_element_img);

		// Image Signature
		if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(signature),
					(uint8_t *)signature)) {
			LOG_ERR("Failed to get region signature");
			return Failure;
		}

		read_address += manifest_flash->max_signature;

		// Modulus length of Public Key
		if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(module_length),
					(uint8_t *)&module_length)) {
			LOG_ERR("Failed to get modulus length");
			return Failure;
		}

		pub_key.mod_length = module_length;
		read_address += sizeof(module_length);

		// Modulus of Public Key
		if (pfr_spi_read(pfr_manifest->image_type, read_address, module_length,
					(uint8_t *)&pub_key.modulus)) {
			LOG_ERR("Failed to get modulus");
			return Failure;
		}
		read_address += module_length;

		// Exponent length of Public Key
		if (pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(exponent_length),
				(uint8_t *)&exponent_length)) {
			LOG_ERR("Failed to get exponent length");
			return Failure;
		}
		read_address += sizeof(exponent_length);

		// Exponent of Public Key
		if (pfr_spi_read(pfr_manifest->image_type, read_address, exponent_length,
				(uint8_t *)&pub_key.exponent)) {
			LOG_ERR("Failed to get exponent");
			return Failure;
		}
		read_address += exponent_length;

		// Region Start Address
		pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(start_address),
				(uint8_t *)&start_address);
		read_address += sizeof(start_address);

		// Region End Address
		pfr_spi_read(pfr_manifest->image_type, read_address, sizeof(end_address),
				(uint8_t *)&end_address);
		read_address += sizeof(end_address);

		LOG_INF("RegionStartAddress: %x, RegionEndAddress: %x",
				start_address, end_address);

		// Bypass verification if validation flag of the region is not set.
		if (!(fw_ver_element_img.flags & PFM_IMAGE_MUST_VALIDATE)) {
			LOG_INF("Digest verification bypassed");
			continue;
		}

		if (flash_verify_contents((struct flash *)pfr_manifest->flash,
				start_address,
				end_address - start_address + sizeof(uint8_t),
				get_hash_engine_instance(),
				manifest_flash->toc_hash_type,
				&getRsaEngineInstance()->base,
				signature,
				manifest_flash->max_signature,
				&pub_key,
				hashStorage,
				manifest_flash->max_signature
				)) {
			LOG_ERR("Digest verification failed");
			return Failure;
		}

		// TODO: key management
		// Validate the key of the region to check whether it was canceled.

		LOG_INF("Digest verification succeeded");
	}

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
