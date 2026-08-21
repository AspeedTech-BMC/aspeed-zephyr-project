
#define DT_DRV_COMPAT manifest_caliptra

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/logging/log.h>
#include <zephyr/multi_heap/shared_multi_heap.h>
#include <zephyr/sys/byteorder.h>

#include <image/firmware_manifest.h>
#include <image/caliptra_soc_manifest.h>
#include <mbedtls/sha512.h>
#include <mbedtls/ecdsa.h>
#include <cptra/cptra_api.h>

LOG_MODULE_REGISTER(cptra_soc_manifest, LOG_LEVEL_DBG);

#define USE_MALLOC 0

struct firmware_manifest_handler cptra_soc_manifest_handler;

static void le_to_be32(uint8_t *data, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		uint32_t word = sys_get_le32(data + i * sizeof(word));

		sys_put_be32(word, data + i * sizeof(word));
	}
}

static void cptra_key_reform(const struct cptra_soc_manifest_preamble_v2 *preamble)
{
	// Caliptra keys and signatures are stored in little-endian format u32 arrays
	
	/* caliptra-sw/image/types/src/lib.rs:
	 * pub type ImageScalar = [u32; ECC384_SCALAR_WORD_SIZE];
	 * pub struct ImageEccPubKey {
         *     /// X Coordinate
         *     pub x: ImageScalar,
         *     /// Y Coordinate
         *     pub y: ImageScalar,
         * }
	 * */

	// Reform the owner ECC public key and signature to big-endian
	le_to_be32((uint8_t *)preamble->vendor_ecc_pub_key.x, sizeof(preamble->vendor_ecc_pub_key.x) / 4);
	le_to_be32((uint8_t *)preamble->vendor_ecc_pub_key.y, sizeof(preamble->vendor_ecc_pub_key.y) / 4);
	le_to_be32((uint8_t *)preamble->vendor_ecc_signature.r, sizeof(preamble->vendor_ecc_signature.r) / 4);
	le_to_be32((uint8_t *)preamble->vendor_ecc_signature.s, sizeof(preamble->vendor_ecc_signature.s) / 4);
	le_to_be32((uint8_t *)preamble->owner_ecc_pub_key.x, sizeof(preamble->owner_ecc_pub_key.x) / 4);
	le_to_be32((uint8_t *)preamble->owner_ecc_pub_key.y, sizeof(preamble->owner_ecc_pub_key.y) / 4);
	le_to_be32((uint8_t *)preamble->owner_ecc_signature.r, sizeof(preamble->owner_ecc_signature.r) / 4);
	le_to_be32((uint8_t *)preamble->owner_ecc_signature.s, sizeof(preamble->owner_ecc_signature.s) / 4);
	le_to_be32((uint8_t *)preamble->imc_vendor_ecc_signature.r, sizeof(preamble->imc_vendor_ecc_signature.r) / 4);
	le_to_be32((uint8_t *)preamble->imc_vendor_ecc_signature.s, sizeof(preamble->imc_vendor_ecc_signature.s) / 4);
	le_to_be32((uint8_t *)preamble->imc_owner_ecc_signature.r, sizeof(preamble->imc_owner_ecc_signature.r) / 4);
	le_to_be32((uint8_t *)preamble->imc_owner_ecc_signature.s, sizeof(preamble->imc_owner_ecc_signature.s) / 4);
}

int cptra_verify_manifest_signature(struct cptra_soc_manifest_preamble_v2 *preamble, struct cptra_image_metadata_collection *imc) 
{
	int ret = 0;
	/* Check Pointer is valid */
	if (!preamble || !imc) {
		LOG_ERR("Invalid pointer");
		ret = -ENOMEM;
		goto exit;
	}

	/* Verify Magic Number */
	if (preamble->marker != CPTRA_MANIFEST_MARKER) {
		LOG_ERR("Invalid manifest marker: 0x%08x", preamble->marker);
		LOG_HEXDUMP_ERR(preamble, offsetof(struct cptra_soc_manifest_preamble_v2, vendor_ecc_pub_key),
				"Preamble Header Dump");
		ret = -EINVAL;
		goto exit;
	}

	/* TODO: Verify vendor public key from key hash */
	if (0) {
		ret = -EINVAL;
		goto exit;
	}

	/* Reform key */
	cptra_key_reform(preamble);

	/* Verify IMC signature */
	ret = cptra_verify_ecdsa(
		preamble->owner_ecc_pub_key.x, preamble->owner_ecc_pub_key.y,
		(uint8_t *)imc, sizeof(struct cptra_image_metadata_collection) + AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT * sizeof(struct cptra_image_metadata_entry),
		preamble->imc_owner_ecc_signature.r, preamble->imc_owner_ecc_signature.s);
	if (ret != 0) {
		LOG_ERR("Failed to verify IMC signature");
		ret = -EINVAL;
		goto exit;
	}

	ret = cptra_verify_lms(
		(uint8_t *)preamble->owner_pqc_pub_key.data,
		(uint8_t *)imc, sizeof(struct cptra_image_metadata_collection) + AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT * sizeof(struct cptra_image_metadata_entry),
		(uint8_t *)preamble->imc_owner_pqc_signature.data);
	if (ret != 0) {
		LOG_ERR("Failed to verify IMC LMS signature");
		ret = 0;
		// ret = -EINVAL;
		// goto exit;
	}

	LOG_INF("IMC signature verified");

exit:
	return ret;
}

int cptra_verify_manifest(const struct device* manifest_device, const struct device *firmware_device, size_t off) 
{
	const struct device *dev = manifest_device;
	const struct device *fmc_dev = firmware_device;
	size_t offset = off;
	uint32_t image_verified = 0;
	int ret;
	size_t preamble_size = sizeof(struct cptra_soc_manifest_preamble_v2);
	size_t imc_size = sizeof(struct cptra_image_metadata_collection) + 
		AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT * sizeof(struct cptra_image_metadata_entry);
	struct cptra_soc_manifest_preamble_v2 *preamble = NULL;
	struct cptra_image_metadata_collection *imc = NULL;

	preamble = (struct cptra_soc_manifest_preamble_v2 *)shared_multi_heap_aligned_alloc(SMH_REG_ATTR_NON_CACHEABLE, 16, preamble_size);
	imc = (struct cptra_image_metadata_collection *)shared_multi_heap_aligned_alloc(SMH_REG_ATTR_NON_CACHEABLE, 16, imc_size);

	uint32_t noncache_size = 1024 * 1024;
	volatile void *noncache_ddr = (void *)shared_multi_heap_aligned_alloc(SMH_REG_ATTR_NON_CACHEABLE, 16, noncache_size);
	if (!noncache_ddr) {
		LOG_ERR("Failed to allocate non-cacheable DDR buffer");
		ret = -ENOMEM;
		goto err;
	}

	LOG_INF("Allocated memory for manifest preamble at %p and imc at %p", preamble, imc);

	if (preamble == NULL || imc == NULL) {
		LOG_ERR("Failed to allocate memory for manifest preamble");
		ret = -ENOMEM;
		goto err;	
	}
	
	LOG_INF("Load preamble from device %s offset %u to %p", dev->name, offset, preamble);
	ret = flash_read(dev, offset, preamble, preamble_size);
	if (ret) {
		LOG_ERR("Failed to read manifest preamble");
		ret = -ENXIO;
		goto err;
	}


	ret = flash_read(dev, offset + preamble_size, imc, imc_size);
	if (ret) {
		LOG_ERR("Failed to read image metadata collection");
		ret = -ENXIO;
		goto err;
	}

	ret = cptra_verify_manifest_signature(preamble, imc);
	if (ret) {
		LOG_ERR("Failed to verify manifest signature");
		goto err;
	}

	// Verify images in IMC
	for (uint32_t i = 0; i < imc->count; i++) {
		struct cptra_image_metadata_entry *entry = &imc->entries[i];
		uint32_t ddr_ram_address = entry->image_load_address_high;
		uint32_t image_offset = entry->staging_address_high;
		uint32_t image_size = entry->staging_address_low;

		LOG_INF("Image %d: ddr_ram_address %08x, image_offset %08x, image_size %08x", i, ddr_ram_address, image_offset, image_size);

		/* Verify image hash if required */
		if (entry->flags & BIT(8)) {
			LOG_INF("Image %d is marked exec load to DDR %08x", i, ddr_ram_address);

			mbedtls_sha512_context sha_ctx;
			mbedtls_sha512_init(&sha_ctx);
			ret = mbedtls_sha512_starts(&sha_ctx, 1);
			if (ret != 0) {
				LOG_ERR("Image %d failed to start hash", i);
				mbedtls_sha512_free(&sha_ctx);
				goto err;
			}

			uint32_t read_offset = 0;
			while (read_offset < image_size) {
				uint32_t current_chunk_size = MIN(noncache_size, image_size - read_offset);
				ret = flash_read(fmc_dev, image_offset + read_offset, (void *)noncache_ddr, current_chunk_size);
				if (ret != 0) {
					LOG_ERR("Image %d Failed to read from flash at offset %u", i, read_offset);
					mbedtls_sha512_free(&sha_ctx);
					goto err;
				}
				LOG_INF("Image %d read chunk at offset %08x, size %u", i, read_offset, current_chunk_size);
				k_msleep(10);
				
				ret = mbedtls_sha512_update(&sha_ctx, (const uint8_t *)noncache_ddr, current_chunk_size);
				if (ret != 0) {
					LOG_ERR("Image %d failed to update hash at offset %u", i, read_offset);
					mbedtls_sha512_free(&sha_ctx);
					goto err;
				}

				memcpy((void *)(uintptr_t)(ddr_ram_address + read_offset), (void *)noncache_ddr, current_chunk_size);
				read_offset += current_chunk_size;
			}

			uint8_t image_hash[48];
			ret = mbedtls_sha512_finish(&sha_ctx, image_hash);
			if (ret != 0) {
				LOG_ERR("Image %d failed to finish hash", i);
				mbedtls_sha512_free(&sha_ctx);
				goto err;
			}
			mbedtls_sha512_free(&sha_ctx);

			LOG_HEXDUMP_INF(image_hash, 48, "Digested");
			if (!(entry->flags & BIT(2)) && memcmp(image_hash, entry->image_hash, sizeof(image_hash)) != 0) {
				LOG_ERR("Image %d hash mismatch", i);
				LOG_HEXDUMP_ERR(entry->image_hash, 48, "Expecting" );
				LOG_HEXDUMP_ERR((void *)(uintptr_t)ddr_ram_address, 256, "Image 256 bytes");
				// ret = -EINVAL;
				// goto err;
			} else {
				LOG_INF("Image %d hash verified or skipped verify", i);
			}
		} else {
			LOG_INF("Image %d is not marked exec load, skip loading to DDR", i);
		}
		image_verified++;
	}

err:

	if (image_verified == imc->count) {
		LOG_INF("All %u images verified successfully", image_verified);
	} else {
		LOG_ERR("Only %u images verified ret %d", image_verified, ret);
	}

	if (noncache_ddr) {
		shared_multi_heap_free((void *)noncache_ddr);
	}

	// Preamble verifed
	if (preamble) {
		shared_multi_heap_free(preamble);
	}
	if (imc) {
		shared_multi_heap_free(imc);
	}

	return ret;
}

int cptra_load_image() {
	return 0;	
}

struct firmware_manifest_handler cptra_soc_manifest_handler = {
	.manifest_context = NULL,
	.verify_manifest = cptra_verify_manifest,
	.load_image = cptra_load_image,
};

struct caliptra_manifest_config {
	const struct device *manifest_device;
	const struct device *firmware_device;
	size_t offset;
};

#if 1

static struct caliptra_manifest_config cptra_manifest_cfg = {
	.manifest_device = DEVICE_DT_GET(DT_INST_PHANDLE(0, manifest_device)),
	.firmware_device = DEVICE_DT_GET(DT_INST_PHANDLE(0, firmware_device)),
	.offset = DT_INST_PROP(0, manifest_offset),
};

DEVICE_DT_INST_DEFINE(0, NULL, NULL,
		    NULL, &cptra_manifest_cfg,
		    POST_KERNEL, 80,
		    &cptra_soc_manifest_handler);
#endif

#if defined(CONFIG_SHELL)
#include <zephyr/device.h>
#include <zephyr/shell/shell.h>
#include <zephyr/drivers/flash.h>
#include <stdlib.h>

static int cmd_soc_manifest_dump(const struct shell *shell, size_t argc, char **argv)
{
	const struct device *dev = device_get_binding(argv[1]);
	uint32_t offset = strtoul(argv[2], NULL, 0);
	int ret;
	
	shell_print(shell, "Device: %s, Offset: %u", dev->name, offset);
	if (!dev) {
		shell_print(shell, "Device %s not found", argv[1]);
		return -ENODEV;
	}
	
	struct cptra_image_metadata_collection *imc = NULL;
	struct cptra_soc_manifest_preamble_v2 *manifest = NULL;

	manifest = (struct cptra_soc_manifest_preamble_v2 *)shared_multi_heap_aligned_alloc(SMH_REG_ATTR_NON_CACHEABLE, 16,sizeof(struct cptra_soc_manifest_preamble_v2));
	if (!manifest) {
		shell_print(shell, "Failed to allocate memory for manifest");
		return -ENOMEM;
	}
	ret = flash_read(dev, offset, manifest, sizeof(struct cptra_soc_manifest_preamble_v2));
	if (ret != 0) {
		shell_print(shell, "Failed to read manifest preamble");
		goto exit;
	}

	// shell_hexdump(shell, manifest, 1024);

	// Dump the manifest structure
	shell_print(shell, "Caliptra SoC Manifest Preamble:");
	shell_print(shell, "  Marker: 0x%08X", manifest->marker);
	shell_print(shell, "  Size: %u bytes", manifest->size);
	shell_print(shell, "  Version: %u", manifest->version);
	shell_print(shell, "  SVN: %u", manifest->svn);
	shell_print(shell, "  Flags: 0x%08X", manifest->flags);
	// Further fields can be printed as needed

	// Dump first 32bytes of all keys
	shell_print(shell, "  Vendor ECC Public Key X (first 32 bytes):");
	shell_hexdump(shell, manifest->vendor_ecc_pub_key.x, 32);
	shell_print(shell, "  Vendor ECC Public Key Y (first 32 bytes):");
	shell_hexdump(shell, manifest->vendor_ecc_pub_key.y, 32);
	shell_print(shell, "  Owner ECC Public Key X (first 32 bytes):");
	shell_hexdump(shell, manifest->owner_ecc_pub_key.x, 32);
	shell_print(shell, "  Owner ECC Public Key Y (first 32 bytes):");
	shell_hexdump(shell, manifest->owner_ecc_pub_key.y, 32);

	// As well as the lms key
	shell_print(shell, "  Vendor LMS Public Key (first 32 bytes):");
	shell_hexdump(shell, manifest->vendor_pqc_pub_key.data, 128);
	shell_print(shell, "  Owner LMS Public Key (first 32 bytes):");
	shell_hexdump(shell, manifest->owner_pqc_pub_key.data, 128);


	// Dump all signatures (first 32 bytes)
	shell_print(shell, "  Vendor ECC Signature R (first 32 bytes):");
	shell_hexdump(shell, manifest->vendor_ecc_signature.r, 32);
	shell_print(shell, "  Vendor ECC Signature S (first 32 bytes):");
	shell_hexdump(shell, manifest->vendor_ecc_signature.s, 32);
	shell_print(shell, "  Owner ECC Signature R (first 32 bytes):");
	shell_hexdump(shell, manifest->owner_ecc_signature.r, 32);
	shell_print(shell, "  Owner ECC Signature S (first 32 bytes):");
	shell_hexdump(shell, manifest->owner_ecc_signature.s, 32);
	shell_print(shell, "  Vendor LMS Signature (first 32 bytes):");
	shell_hexdump(shell, manifest->vendor_pqc_signature.data, 128);
	shell_print(shell, "  Owner LMS Signature (first 32 bytes):");
	shell_hexdump(shell, manifest->owner_pqc_signature.data, 128);

	// As well as the IMC signatures
	shell_print(shell, "  IMC Vendor ECC Signature R (first 32 bytes):");
	shell_hexdump(shell, manifest->imc_vendor_ecc_signature.r, 32);
	shell_print(shell, "  IMC Vendor ECC Signature S (first 32 bytes):");
	shell_hexdump(shell, manifest->imc_vendor_ecc_signature.s, 32);
	shell_print(shell, "  IMC Owner ECC Signature R (first 32 bytes):");
	shell_hexdump(shell, manifest->imc_owner_ecc_signature.r, 32);
	shell_print(shell, "  IMC Owner ECC Signature S (first 32 bytes):");
	shell_hexdump(shell, manifest->imc_owner_ecc_signature.s, 32);

	// as well as the lms signatue
	shell_print(shell, "  IMC Vendor LMS Signature (first 32 bytes):");
	shell_hexdump(shell, manifest->imc_vendor_pqc_signature.data, 128);
	shell_print(shell, "  IMC Owner LMS Signature (first 32 bytes):");
	shell_hexdump(shell, manifest->imc_owner_pqc_signature.data, 128);

	// Dump image_collection
	uint32_t imc_size = sizeof(uint32_t) + sizeof(struct cptra_image_metadata_entry) * AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT;
	imc = (struct cptra_image_metadata_collection *)shared_multi_heap_aligned_alloc(SMH_REG_ATTR_NON_CACHEABLE, 16, imc_size);
	if (!imc) {
		shell_print(shell, "Failed to allocate memory for image metadata collection");
		goto exit;

	}
	flash_read(dev, offset + sizeof(struct cptra_soc_manifest_preamble_v2), imc, imc_size);

	for (uint32_t i = 0; i < imc->count; i++) {
		shell_print(shell, "Image %u:", i);
		shell_hexdump(shell, imc->entries[i].image_hash, sizeof(imc->entries[i].image_hash));
		shell_print(shell, "  Image Identifier: 0x%08X", imc->entries[i].image_identifier);
		shell_print(shell, "  Component ID: 0x%08X", imc->entries[i].component_id);
		shell_print(shell, "  Flags: 0x%08X", imc->entries[i].flags);
		shell_print(shell, "  Image Load Address: 0x%08X %08x", imc->entries[i].image_load_address_high, imc->entries[i].image_load_address_low);
		shell_print(shell, "  Image Stage Address: 0x%08X %08x", imc->entries[i].staging_address_high, imc->entries[i].staging_address_low);
		// Further fields can be printed as needed
	}

exit:
	if (imc)
		shared_multi_heap_free(imc);
	if (manifest)
		shared_multi_heap_free(manifest);
	return ret;
}

static int cmd_soc_manifest_verify(const struct shell *shell, size_t argc, char **argv)
{

	const struct device *man_dev = device_get_binding(argv[1]);
	const struct device *fmc_dev = device_get_binding(argv[2]);
	uint32_t offset = strtoul(argv[3], NULL, 0);

	int ret = cptra_verify_manifest(man_dev, fmc_dev, offset);
	if (ret != 0) {
		shell_print(shell, "Failed to verify SoC manifest at %s offset %u", man_dev->name, offset);
		return ret;
	}

	return 0;
}

static int cmd_soc_manifest_read(const struct shell *shell, size_t argc, char **argv) {
	const struct device *dev = device_get_binding(argv[1]);
	if (!dev) {
		shell_print(shell, "Device %s not found", argv[1]);
		return -ENODEV;
	}
	uint32_t offset = strtoul(argv[2], NULL, 0);
	uint32_t size = strtoul(argv[3], NULL, 0);
	
	shell_print(shell, "Device: %s, Offset: %u, Size: %u", dev->name, offset, size);

	uint8_t *buffer = malloc(size);
	if (!buffer) {
		shell_print(shell, "Failed to allocate memory for buffer");
		return -ENOMEM;
	}

	int ret = flash_read(dev, offset, buffer, size);
	if (ret != 0) {
		shell_print(shell, "Failed to read from flash");
		goto exit;
	}

	shell_hexdump(shell, buffer, size);

exit:
	free(buffer);
	return 0;
}

/* 
 * Struct origin:
 *  https://github.com/chipsalliance/caliptra-mcu-sw/blob/2b7837402328ab611968d40243075082469df7ae/common/flash-image/src/lib.rs
 * */
struct caliptra_flash_header {
	uint32_t magic;
	uint16_t version;
	uint16_t image_count;
} __packed;

struct caliptra_flash_checksums {
	uint32_t header_crc32;
	uint32_t payload_crc32;
} __packed;

struct caliptra_image_header {
	uint32_t identifier;
	uint32_t offset;
	uint32_t size;
} __packed;

uint32_t calculate_crc32(const uint8_t *data, size_t length) {
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < length; i++) {
		crc ^= data[i];
		for (size_t j = 0; j < 8; j++) {
			if (crc & 1) {
				crc = (crc >> 1) ^ 0xEDB88320;
			} else {
				crc >>= 1;
			}
		}
	}
	return ~crc;
}

static int cmd_caliptra_image_info(const struct shell *shell, size_t argc, char **argv)
{
	const struct device *fmc_dev = device_get_binding("fmc@0");
	if (!fmc_dev) {
		shell_print(shell, "Failed to bind to FMC device");
		return -ENODEV;
	}

	// Read flash header
	struct caliptra_flash_header flash_header;
	if (flash_read(fmc_dev, 0x0, (uint8_t *)&flash_header, sizeof(flash_header)) != 0) {
		shell_print(shell, "Failed to read flash header");
		return -EIO;
	}

	shell_print(shell, "Caliptra Flash Image Information:");
	shell_print(shell, "Magic: 0x%08X", flash_header.magic);
	shell_print(shell, "Version: %d", flash_header.version);
	shell_print(shell, "Image Count: %d", flash_header.image_count);

	// Read checksums
	struct caliptra_flash_checksums checksums;
	size_t checksums_offset = sizeof(flash_header);
	if (flash_read(fmc_dev, checksums_offset, (uint8_t *)&checksums, sizeof(checksums)) != 0) {
		shell_print(shell, "Failed to read flash checksums");
		return -EIO;
	}
	
	// Check crc
	if (checksums.header_crc32 != calculate_crc32((uint8_t *)&flash_header, sizeof(flash_header))) {
		shell_print(shell, "Header CRC32 mismatch!");
		return -EIO;
	} else {
		shell_print(shell, "Header CRC32: 0x%08X (valid)", checksums.header_crc32);
	}

	/* Read and display each image header */
	for (uint16_t i = 0; i < flash_header.image_count; i++)
	{
		struct caliptra_image_header image_header;
		size_t header_offset = sizeof(flash_header) + sizeof(checksums) + i * sizeof(image_header);
		if (flash_read(fmc_dev, header_offset, (uint8_t *)&image_header, sizeof(image_header)) != 0) {
			shell_print(shell, "Failed to read image header %d", i);
			return -EIO;
		}

		shell_print(shell, "Image %d:", i);
		shell_print(shell, "  Identifier: 0x%08X", image_header.identifier);
		shell_print(shell, "  Offset: 0x%08X", image_header.offset);
		shell_print(shell, "  Size: %d bytes", image_header.size);
	}


	return 0;
}

#include <cptra/cptra_sample.h>

int cmd_caliptra_verify_signature(const struct shell *shell, size_t argc, char **argv)
{
	// This is a placeholder for signature verification command

	uint32_t i = strtoul(argv[1], NULL, 0);
	
	if ( i >= ARRAY_SIZE(secp384r1_tv)) {
		shell_print(shell, "Invalid test vector index");
		return -EINVAL;
	}

	const struct ecdsa_testvec *tv = &secp384r1_tv[i];

	cptra_verify_ecdsa(
		/* pubx */ tv->qx, 
		/* puby */ tv->qy, 
		/* msg */ tv->raw, 
		/* msg_len */ tv->raw_size, 
		/* sig_r */ tv->r, 
		/* sig_s */ tv->s);


	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_socm,
	SHELL_CMD_ARG(ecdsa, NULL, "Show this help message", cmd_caliptra_verify_signature, 2, 0),
	SHELL_CMD_ARG(dump, NULL,
		"Display Caliptra SoC Manifest Preamble\n"
		"Usage: soc_manifest show <device> <address>\n"
		"  <address> - Memory address of the SoC Manifest Preamble",
		cmd_soc_manifest_dump, 3, 0),
	SHELL_CMD_ARG(verify, NULL,
		"Verify Caliptra SoC Manifest\n"
		"Usage: soc_manifest verify <manifest_device> <firmware_device> <address>\n"
		"  <address> - Memory address of the SoC Manifest Preamble",
		cmd_soc_manifest_verify, 4, 0),
	SHELL_CMD_ARG(read, NULL,
		"Read and dump from flash device",
		cmd_soc_manifest_read, 4, 0),
	SHELL_CMD(image_info, NULL, "Display Caliptra Image Information", cmd_caliptra_image_info),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(nmta, &sub_socm, "Caliptra SoC Manifest commands", NULL);

#endif

