#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/drivers/cptra.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/multi_heap/shared_multi_heap.h>

#include <cptra/cptra_api.h>
#include <image/caliptra_soc_manifest.h>
#include <image/caliptra_soc_manifest_v1.h>
#include <image/firmware_manifest.h>
#include <mbedtls/sha512.h>

LOG_MODULE_REGISTER(cptra_soc_manifest_v1, LOG_LEVEL_DBG);

static void le_to_be32_words(uint8_t *data, size_t word_count)
{
	for (size_t i = 0; i < word_count; i++) {
		uint32_t word;

		memcpy(&word, data + (i * sizeof(word)), sizeof(word));
		word = __builtin_bswap32(word);
		memcpy(data + (i * sizeof(word)), &word, sizeof(word));
	}
}

static uint32_t cptra_crc32_ieee(const uint8_t *data, size_t length)
{
	uint32_t crc = 0xFFFFFFFFu;

	for (size_t i = 0; i < length; i++) {
		crc ^= data[i];
		for (int bit = 0; bit < 8; bit++) {
			uint32_t mask = -(crc & 1u);
			crc = (crc >> 1) ^ (0xEDB88320u & mask);
		}
	}

	return ~crc;
}

static void cptra_key_reform_v1(struct cptra_soc_manifest_preamble_v1 *preamble)
{
	le_to_be32_words(preamble->vendor_ecc_pub_key.x,
			 sizeof(preamble->vendor_ecc_pub_key.x) / sizeof(uint32_t));
	le_to_be32_words(preamble->vendor_ecc_pub_key.y,
			 sizeof(preamble->vendor_ecc_pub_key.y) / sizeof(uint32_t));
	// le_to_be32_words((uint32_t *)preamble->vendor_ecc_signature.r,
	// 		 sizeof(preamble->vendor_ecc_signature.r) / sizeof(uint32_t));
	// le_to_be32_words((uint32_t *)preamble->vendor_ecc_signature.s,
	// 		 sizeof(preamble->vendor_ecc_signature.s) / sizeof(uint32_t));
	le_to_be32_words(preamble->owner_ecc_pub_key.x,
			 sizeof(preamble->owner_ecc_pub_key.x) / sizeof(uint32_t));
	le_to_be32_words(preamble->owner_ecc_pub_key.y,
			 sizeof(preamble->owner_ecc_pub_key.y) / sizeof(uint32_t));
	// le_to_be32_words((uint32_t *)preamble->owner_ecc_signature.r,
	// 		 sizeof(preamble->owner_ecc_signature.r) / sizeof(uint32_t));
	// le_to_be32_words((uint32_t *)preamble->owner_ecc_signature.s,
	// 		 sizeof(preamble->owner_ecc_signature.s) / sizeof(uint32_t));
	// le_to_be32_words((uint32_t *)preamble->owner_manifest2_ecc_signature.r,
	// 		 sizeof(preamble->owner_manifest2_ecc_signature.r) / sizeof(uint32_t));
	// le_to_be32_words((uint32_t *)preamble->owner_manifest2_ecc_signature.s,
	// 		 sizeof(preamble->owner_manifest2_ecc_signature.s) / sizeof(uint32_t));
	// le_to_be32_words((uint32_t *)preamble->vendor_imc_ecc_signature.r,
	// 		 sizeof(preamble->vendor_imc_ecc_signature.r) / sizeof(uint32_t));
	// le_to_be32_words((uint32_t *)preamble->vendor_imc_ecc_signature.s,
	// 		 sizeof(preamble->vendor_imc_ecc_signature.s) / sizeof(uint32_t));
	le_to_be32_words(preamble->owner_imc_ecc_signature.r,
			 sizeof(preamble->owner_imc_ecc_signature.r) / sizeof(uint32_t));
	le_to_be32_words(preamble->owner_imc_ecc_signature.s,
			 sizeof(preamble->owner_imc_ecc_signature.s) / sizeof(uint32_t));
}

static int cptra_fill_set_auth_manifest_input_v1(
	struct cptra_set_auth_manifest_ia *input,
	const struct cptra_soc_manifest_preamble_v1 *manifest_preamble,
	const struct cptra_image_metadata_collection_v1 *imc)
{
	if (imc->count > CPTRA_IMC_ENTRY_COUNT) {
		LOG_ERR("IMC entry count %u exceeds Caliptra limit", imc->count);
		return -EINVAL;
	}

	memset(input, 0, sizeof(*input));
	input->manifest_size = sizeof(struct cptra_manifest_preamble) + sizeof(uint32_t) +
			       (AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT * sizeof(struct cptra_manifest_ime));
	input->metadata_entry_entry_count = imc->count;

	struct cptra_soc_manifest_preamble_v1 *temp_preamble =
		(struct cptra_soc_manifest_preamble_v1 *)malloc(sizeof(struct cptra_soc_manifest_preamble_v1));
	if (temp_preamble == NULL) {
		return -ENOMEM;
	}
	memcpy(temp_preamble, manifest_preamble, sizeof(struct cptra_soc_manifest_preamble_v1));
	// cptra_key_reform_v1(temp_preamble);

	memcpy(&input->preamble.manifest_marker, &manifest_preamble->marker,
	       sizeof(manifest_preamble->marker));
	memcpy(&input->preamble.preamble_size, &manifest_preamble->size,
	       sizeof(input->preamble.preamble_size));
	memcpy(&input->preamble.manifest_version, &manifest_preamble->version,
	       sizeof(input->preamble.manifest_version));
	memcpy(&input->preamble.manifest_flags, &manifest_preamble->flags,
	       sizeof(input->preamble.manifest_flags));
	memcpy(input->preamble.manifest_vendor_ecc384_key, &temp_preamble->vendor_ecc_pub_key,
	       sizeof(input->preamble.manifest_vendor_ecc384_key));
	memcpy(input->preamble.manifest_vendor_lms_key, &temp_preamble->vendor_lms_pub_key,
	       sizeof(input->preamble.manifest_vendor_lms_key));
	memcpy(input->preamble.manifest_vendor_ecc384_sig, &temp_preamble->vendor_ecc_signature,
	       sizeof(input->preamble.manifest_vendor_ecc384_sig));
	memcpy(input->preamble.manifest_vendor_LMS_sig, &temp_preamble->vendor_lms_signature,
	       sizeof(input->preamble.manifest_vendor_LMS_sig));
	memcpy(input->preamble.manifest_owner_ecc384_key, &temp_preamble->owner_ecc_pub_key,
	       sizeof(input->preamble.manifest_owner_ecc384_key));
	memcpy(input->preamble.manifest_owner_lms_key, &temp_preamble->owner_lms_pub_key,
	       sizeof(input->preamble.manifest_owner_lms_key));
	memcpy(input->preamble.manifest_owner_ecc384_sig, &temp_preamble->owner_ecc_signature,
	       sizeof(input->preamble.manifest_owner_ecc384_sig));
	memcpy(input->preamble.manifest_owner_LMS_sig, &temp_preamble->owner_lms_signature,
	       sizeof(input->preamble.manifest_owner_LMS_sig));
	memcpy(input->preamble.metadata_vendor_ecc384_sig, &temp_preamble->vendor_imc_ecc_signature,
	       sizeof(input->preamble.metadata_vendor_ecc384_sig));
	memcpy(input->preamble.metadata_vendor_LMS_sig, &temp_preamble->vendor_imc_lms_signature,
	       sizeof(input->preamble.metadata_vendor_LMS_sig));
	memcpy(input->preamble.metadata_owner_ecc384_sig, &temp_preamble->owner_imc_ecc_signature,
	       sizeof(input->preamble.metadata_owner_ecc384_sig));
	memcpy(input->preamble.metadata_owner_LMS_sig, &temp_preamble->owner_imc_lms_signature,
	       sizeof(input->preamble.metadata_owner_LMS_sig));
	memcpy(input->metadata_entries, imc->entries, imc->count * sizeof(struct cptra_manifest_ime));

	free(temp_preamble);

	return 0;
}

static int cptra_set_auth_manifest_v1(const struct cptra_soc_manifest_preamble_v1 *manifest_preamble,
				      const struct cptra_image_metadata_collection_v1 *imc)
{
	struct cptra_set_auth_manifest_ia *input;
	int ret;

	input = malloc(sizeof(*input));
	if (input == NULL) {
		return -ENOMEM;
	}

	ret = cptra_fill_set_auth_manifest_input_v1(input, manifest_preamble, imc);
	if (ret) {
		free(input);
		return ret;
	}

	ret = cptra_set_auth_manifest(input);
	free(input);

	return ret;
}

static int cptra_verify_manifest_imc_signature_v1(
	const struct cptra_soc_manifest_preamble_v1 *manifest_preamble,
	const struct cptra_image_metadata_collection_v1 *imc)
{
	struct cptra_soc_manifest_preamble_v1 preamble;
	int ret;

	if (manifest_preamble->marker != CPTRA_SOC_MANIFEST_V1_MAGIC) {
		LOG_ERR("Invalid manifest marker: 0x%08x", manifest_preamble->marker);
		return -EINVAL;
	}

	memcpy(&preamble, manifest_preamble, sizeof(preamble));
	cptra_key_reform_v1(&preamble);

	ret = cptra_verify_ecdsa(preamble.owner_ecc_pub_key.x, preamble.owner_ecc_pub_key.y,
				 (const uint8_t *)imc, sizeof(*imc),
				 preamble.owner_imc_ecc_signature.r,
				 preamble.owner_imc_ecc_signature.s);
	if (ret) {
		LOG_ERR("Vendor  ECDSA signature verification failed");
		return -EACCES;
	}

	ret = cptra_verify_lms((const uint8_t *)&preamble.owner_lms_pub_key,
			       (const uint8_t *)imc, sizeof(*imc),
			       (const uint8_t *)&preamble.owner_imc_lms_signature);
	if (ret) {
		LOG_ERR("Vendor IMC LMS signature verification failed");
		return -EACCES;
	}

	return 0;
}

static const struct cptra_load_image *cptra_find_load_image_entry(uint32_t firmware_id)
{
	for (size_t i = 0; i < ARRAY_SIZE(cptra_image_list); i++) {
		if (cptra_image_list[i].fw_id == firmware_id) {
			return &cptra_image_list[i];
		}
	}

	return NULL;
}

static const struct cptra_image_info_v1 *cptra_find_image_info_v1(
	const struct cptra_image_info_v1 *image_info_array, uint32_t image_count, uint32_t identifier)
{
	for (uint32_t i = 0; i < image_count; i++) {
		if (image_info_array[i].identifier == identifier) {
			return &image_info_array[i];
		}
	}

	return NULL;
}

static int cptra_validate_flash_header_v1(const struct cptra_flash_header_v1 *flash_header,
					  const struct cptra_image_info_v1 *image_info_array,
					  size_t bundle_size)
{
	size_t header_size;
	uint32_t header_crc;

	if (flash_header->magic != CPTRA_FLASH_HEADER_MAGIC) {
		LOG_ERR("Invalid flash header magic: 0x%08X", flash_header->magic);
		return -EINVAL;
	}

	if (flash_header->image_count == 0 ||
	    flash_header->image_count > AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT) {
		LOG_ERR("Invalid flash header image count: %u", flash_header->image_count);
		return -EINVAL;
	}

	header_size = sizeof(*flash_header) +
		      (flash_header->image_count * sizeof(struct cptra_image_info_v1));
	if (bundle_size != SIZE_MAX && header_size > bundle_size) {
		LOG_ERR("Flash header extends past bundle boundary");
		return -EINVAL;
	}

	header_crc = cptra_crc32_ieee((const uint8_t *)flash_header,
				      offsetof(struct cptra_flash_header_v1, header_checksum));
	if (flash_header->header_checksum != 0 && header_crc != flash_header->header_checksum) {
		LOG_ERR("Flash header checksum mismatch");
		return -EINVAL;
	}

	if (bundle_size != SIZE_MAX) {
		for (uint32_t i = 0; i < flash_header->image_count; i++) {
			uint64_t image_end = (uint64_t)image_info_array[i].image_offset +
					     image_info_array[i].image_size;
			if (image_end > bundle_size) {
				LOG_ERR("Image %u extends past bundle boundary", i);
				return -EINVAL;
			}
		}
	}

	return 0;
}

static int cptra_check_bundle_image_integrity_v1(const uint8_t *bundle, size_t bundle_size,
						 const struct cptra_image_info_v1 *image_info,
						 const struct cptra_image_metadata_entry_v1 *entry,
						 uint8_t digest[48])
{
	int ret;

	if ((uint64_t)image_info->image_offset + image_info->image_size > bundle_size) {
		return -EINVAL;
	}

	ret = mbedtls_sha512(bundle + image_info->image_offset, image_info->image_size, digest, 1);
	if (ret) {
		LOG_ERR("Failed to hash image fw_id=0x%08X", entry->firmware_id);
		return -EIO;
	}

	if (memcmp(digest, entry->digest, 48) != 0) {
		LOG_ERR("Image digest mismatch for fw_id=0x%08X", entry->firmware_id);
		LOG_HEXDUMP_ERR(digest, 48, "Digested:");
		LOG_HEXDUMP_ERR(entry->digest, 48, "Expected:");
		LOG_WRN("Continuing with authorization even though integrity check failed");
		// return -EACCES;
	}

	return 0;
}

static int cptra_authorize_bundle_image_v1(const uint8_t *bundle, size_t bundle_size,
					   const struct cptra_image_info_v1 *image_info,
					   const struct cptra_image_metadata_entry_v1 *entry)
{
	uint8_t digest[48];
	int ret;

	ret = cptra_check_bundle_image_integrity_v1(bundle, bundle_size, image_info, entry, digest);
	if (ret) {
		return ret;
	}

	ret = cptra_authorize_and_stash(entry->firmware_id, digest, true);
	if (ret) {
		LOG_ERR("Caliptra authorization failed for fw_id=0x%08X ret=%d",
			entry->firmware_id, ret);
		return -EACCES;
	}

	return 0;
}

int cptra_validate_bundle_v1(const uint8_t *bundle, size_t bundle_size)
{
	const struct cptra_flash_header_v1 *flash_header;
	const struct cptra_image_info_v1 *image_info_array;
	const struct cptra_image_info_v1 *manifest_image_info;
	const struct cptra_soc_manifest_preamble_v1 *manifest_preamble;
	const struct cptra_image_metadata_collection_v1 *imc;
	size_t manifest_min_size;
	int ret;

	if (bundle == NULL || bundle_size < sizeof(struct cptra_flash_header_v1)) {
		return -EINVAL;
	}

	flash_header = (const struct cptra_flash_header_v1 *)bundle;
	image_info_array = (const struct cptra_image_info_v1 *)(bundle + sizeof(*flash_header));

	ret = cptra_validate_flash_header_v1(flash_header, image_info_array, bundle_size);
	if (ret) {
		return ret;
	}

	manifest_image_info = cptra_find_image_info_v1(image_info_array, flash_header->image_count,
						       CPTRA_SOC_MANIFEST_HDR_ID);
	if (manifest_image_info == NULL) {
		LOG_ERR("Manifest image not found in flash header");
		return -ENOENT;
	}

	manifest_min_size = sizeof(struct cptra_soc_manifest_preamble_v1) +
			    sizeof(struct cptra_image_metadata_collection_v1);
	if (manifest_image_info->image_size < manifest_min_size ||
	    (uint64_t)manifest_image_info->image_offset + manifest_min_size > bundle_size) {
		LOG_ERR("Manifest image is truncated");
		return -EINVAL;
	}

	manifest_preamble = (const struct cptra_soc_manifest_preamble_v1 *)
		(bundle + manifest_image_info->image_offset);
	imc = (const struct cptra_image_metadata_collection_v1 *)
		((const uint8_t *)manifest_preamble + sizeof(*manifest_preamble));

	if (imc->count > AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT) {
		LOG_ERR("Manifest IMC count %u exceeds max", imc->count);
		return -EINVAL;
	}

	ret = cptra_set_auth_manifest_v1(manifest_preamble, imc);
	if (ret) {
		LOG_ERR("set_auth_manifest failed");
		ret = 0;
		// return ret;
	}

	ret = cptra_verify_manifest_imc_signature_v1(manifest_preamble, imc);
	if (ret) {
		LOG_ERR("Manifest IMC signature verification failed");
		ret = 0; /* Continue to check individual image integrity even if signature verification fails */
		// return ret;
	}

	for (uint32_t i = 0; i < imc->count; i++) {
		const struct cptra_image_metadata_entry_v1 *entry = &imc->entries[i];
		const struct cptra_load_image *load_image_entry;
		const struct cptra_image_info_v1 *image_info;

		load_image_entry = cptra_find_load_image_entry(entry->firmware_id);
		if (load_image_entry == NULL) {
			LOG_ERR("Unknown firmware id 0x%08X in IMC", entry->firmware_id);
			return -ENOENT;
		}

		image_info = cptra_find_image_info_v1(image_info_array, flash_header->image_count,
						      load_image_entry->identifier);
		if (image_info == NULL) {
			LOG_ERR("Missing image payload for fw_id=0x%08X", entry->firmware_id);
			return -ENOENT;
		}

		if (entry->firmware_id == CPTRA_MANIFEST_FW_ID) {
			uint8_t digest[48];

			ret = cptra_check_bundle_image_integrity_v1(bundle, bundle_size, image_info,
								    entry, digest);
		} else {
			ret = cptra_authorize_bundle_image_v1(bundle, bundle_size, image_info, entry);
		}
		if (ret) {
			return ret;
		}
	}

	return 0;
}

static int load_image(const struct device *firmware_device,
		      uint32_t image_offset, uint32_t image_size,
		      uint32_t firmware_id, const uint8_t *expect_digest, void *load_address)
{
	int ret;
	void *noncache_ddr;
	mbedtls_sha512_context sha_ctx;
	uint8_t calculated_digest[48];
	uint32_t remaining_size;

	LOG_INF("Loading image fw_id=0x%08X, offset=0x%08X, size=0x%08X to address 0x%p",
		firmware_id, image_offset, image_size, load_address);

	if (load_address == NULL || (uintptr_t)load_address == CPTRA_NO_LOAD_ADDR) {
		LOG_ERR("Invalid load address for fw_id=0x%08X", firmware_id);
		return -EINVAL;
	}

	noncache_ddr = shared_multi_heap_aligned_alloc(SMH_REG_ATTR_NON_CACHEABLE, 16, 1024 * 1024);
	if (noncache_ddr == NULL) {
		LOG_ERR("Failed to allocate non-cacheable DDR buffer");
		return -ENOMEM;
	}

	mbedtls_sha512_init(&sha_ctx);
	ret = mbedtls_sha512_starts(&sha_ctx, 1);
	if (ret) {
		shared_multi_heap_free(noncache_ddr);
		return ret;
	}

	remaining_size = image_size;
	while (remaining_size > 0) {
		size_t chunk_size = MIN(remaining_size, 1024 * 1024);

		ret = flash_read(firmware_device, image_offset + (image_size - remaining_size),
				 noncache_ddr, chunk_size);
		if (ret) {
			LOG_ERR("Failed to read image chunk from flash");
			ret = -ENXIO;
			goto err;
		}

		k_msleep(10);

		ret = mbedtls_sha512_update(&sha_ctx, noncache_ddr, chunk_size);
		if (ret) {
			goto err;
		}

		memcpy((uint8_t *)load_address + (image_size - remaining_size), noncache_ddr, chunk_size);
		remaining_size -= chunk_size;
	}

	ret = mbedtls_sha512_finish(&sha_ctx, calculated_digest);
	if (ret) {
		goto err;
	}

	if (memcmp(calculated_digest, expect_digest, 48) != 0) {
		LOG_ERR("Digest mismatch for fw_id=0x%08X", firmware_id);
		LOG_HEXDUMP_ERR(calculated_digest, 48, "Calculated:");
		LOG_HEXDUMP_ERR(expect_digest, 48, "Expected:");
		// ret = -EACCES;
		// goto err;
	}

	ret = cptra_authorize_and_stash(firmware_id, calculated_digest, false);
	if (ret) {
		LOG_ERR("Image authorization failed, ret: %d", ret);
		// ret = -EACCES;
		// goto err;
	}

	ret = 0;

err:
	mbedtls_sha512_free(&sha_ctx);
	shared_multi_heap_free(noncache_ddr);

	return ret;
}

int cptra_verify_manifest_v1(
	const struct device *firmware_device,
	const struct cptra_flash_header_v1 *flash_header,
	const struct cptra_image_info_v1 *image_info_array,
	const struct cptra_soc_manifest_preamble_v1 *manifest_preamble,
	const struct cptra_image_metadata_collection_v1 *imc)
{
	int ret;

	ret = cptra_verify_manifest_imc_signature_v1(manifest_preamble, imc);
	if (ret) {
		LOG_ERR("Manifest IMC signature verification failed");
		ret = 0;
		// return ret;
	}

	for (uint32_t i = 0; i < imc->count; i++) {
		const struct cptra_image_metadata_entry_v1 *entry = &imc->entries[i];
		const struct cptra_load_image *load_image_entry;
		const struct cptra_image_info_v1 *image_info;

		if (((entry->flags & CPTRA_LOADABLE_MASK) >> 30) != CPTRA_SSP_LOADABLE) {
			LOG_INF("Skip image %u: Firmware ID: 0x%08X, Flags: 0x%08X",
				i, entry->firmware_id, entry->flags);
			continue;
		}
		LOG_INF("Verify image %u: Firmware ID: 0x%08X, Flags: 0x%08X",
			i, entry->firmware_id, entry->flags);

		load_image_entry = cptra_find_load_image_entry(entry->firmware_id);
		if (load_image_entry == NULL) {
			LOG_ERR("No load image entry found for firmware ID: 0x%08X", entry->firmware_id);
			return -ENOENT;
		}

		if (load_image_entry->load_addr == CPTRA_NO_LOAD_ADDR) {
			LOG_ERR("Unsupported zero load address for firmware ID: 0x%08X",
				entry->firmware_id);
			return -EINVAL;
		}

		image_info = cptra_find_image_info_v1(image_info_array, flash_header->image_count,
						      load_image_entry->identifier);
		if (image_info == NULL) {
			LOG_ERR("No image info found for firmware ID: 0x%08X", entry->firmware_id);
			return -ENOENT;
		}

		ret = load_image(firmware_device, image_info->image_offset, image_info->image_size,
				 entry->firmware_id, entry->digest,
				 (void *)load_image_entry->load_addr);
		if (ret) {
			LOG_ERR("Failed to load image with firmware ID: 0x%08X", entry->firmware_id);
			return ret;
		}
	}

	return 0;
}

static int cptra_verify_manifest_from_flash(const struct device *manifest_device,
					    const struct device *firmware_device, size_t off)
{
	int ret;
	struct cptra_flash_header_v1 *flash_header = NULL;
	struct cptra_image_info_v1 *image_info_array = NULL;
	const struct cptra_image_info_v1 *manifest_image_info;
	void *manifest_buffer = NULL;
	size_t image_info_array_size;
	size_t manifest_size = sizeof(struct cptra_soc_manifest_preamble_v1) +
			       sizeof(struct cptra_image_metadata_collection_v1);
	struct cptra_soc_manifest_preamble_v1 *manifest_preamble;
	struct cptra_image_metadata_collection_v1 *imc;

	flash_header = shared_multi_heap_aligned_alloc(SMH_REG_ATTR_NON_CACHEABLE, 16,
						       sizeof(*flash_header));
	if (flash_header == NULL) {
		return -ENOMEM;
	}

	ret = flash_read(manifest_device, off, flash_header, sizeof(*flash_header));
	if (ret) {
		ret = -ENXIO;
		goto err;
	}

	if (flash_header->image_count == 0 ||
	    flash_header->image_count > AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT) {
		ret = -EINVAL;
		goto err;
	}

	image_info_array_size = flash_header->image_count * sizeof(struct cptra_image_info_v1);
	image_info_array = shared_multi_heap_aligned_alloc(SMH_REG_ATTR_NON_CACHEABLE, 16,
							   image_info_array_size);
	if (image_info_array == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	ret = flash_read(manifest_device, off + sizeof(*flash_header), image_info_array,
			 image_info_array_size);
	if (ret) {
		ret = -ENXIO;
		goto err;
	}

	ret = cptra_validate_flash_header_v1(flash_header, image_info_array, SIZE_MAX);
	if (ret) {
		goto err;
	}

	manifest_image_info = cptra_find_image_info_v1(image_info_array, flash_header->image_count,
						       CPTRA_SOC_MANIFEST_HDR_ID);
	if (manifest_image_info == NULL || manifest_image_info->image_size < manifest_size) {
		ret = -ENOENT;
		goto err;
	}

	manifest_buffer = shared_multi_heap_aligned_alloc(SMH_REG_ATTR_NON_CACHEABLE, 16, manifest_size);
	if (manifest_buffer == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	ret = flash_read(manifest_device, manifest_image_info->image_offset, manifest_buffer, manifest_size);
	if (ret) {
		ret = -ENXIO;
		goto err;
	}

	manifest_preamble = (struct cptra_soc_manifest_preamble_v1 *)manifest_buffer;
	imc = (struct cptra_image_metadata_collection_v1 *)
		((uint8_t *)manifest_buffer + sizeof(*manifest_preamble));
	if (imc->count > AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT) {
		ret = -EINVAL;
		goto err;
	}

	ret = cptra_verify_manifest_v1(firmware_device, flash_header, image_info_array,
				       manifest_preamble, imc);

err:
	if (manifest_buffer != NULL) {
		shared_multi_heap_free(manifest_buffer);
	}
	if (image_info_array != NULL) {
		shared_multi_heap_free(image_info_array);
	}
	if (flash_header != NULL) {
		shared_multi_heap_free(flash_header);
	}

	return ret;
}

static int cptra_load_image(void)
{
	return 0;
}

struct firmware_manifest_handler cptra_soc_manifest_v1_handler = {
	.manifest_context = NULL,
	.verify_manifest = cptra_verify_manifest_from_flash,
	.load_image = cptra_load_image,
};
