/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <fit.h>
#include <manifest.h>
#include <spi.h>

#include <zephyr/drivers/cptra.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/crc.h>

LOG_MODULE_REGISTER(cptra_manifest, CONFIG_LOG_DEFAULT_LEVEL);

static void *cptra_read(struct manifest_load_info *info, int size)
{
	int count = 0;
	void *buf = NULL;

	buf = cptra_manifest_buffer_addr(info->write_sector);

	count = info->read((struct fit_load_info *)info, info->read_sector, size, buf);
	if (count <= 0)
		return NULL;

	if (count != size)
		return NULL;

	info->read_sector += count;
	info->write_sector += count;

	return buf;
}

static int manifest_crc32_check(struct manifest_image_info *man, struct manifest_load_info *info)
{
#ifdef CONFIG_CRC
	int img_size = 0;
	uint32_t hdr_crc32 = 0;
	uint32_t payload_crc32 = 0;
	uint32_t payload_size = 0;

	/* Check the flash image header crc checksum */
	hdr_crc32 = crc32_ieee((uint8_t *)man->hdr, sizeof(struct cptra_manifest_hdr));
	if (hdr_crc32 != man->chk->hdr_checksum) {
		LOG_ERR("Check flash image header checksum ...fail.");
		return CPTRA_ERR_HDR_CHKSUM;
	}

	/* Get all image size */
	img_size = cptra_get_all_image_size(man);
	if (img_size < 0)
		return CPTRA_ERR_IMAGE_SIZE_OVERFLOW;

	/* Check the flash image payload crc checksum */
	payload_size = sizeof(struct cptra_image_info) * man->hdr->img_count + img_size;
	payload_crc32 = crc32_ieee((uint8_t *)man->img_info, payload_size);
	if (payload_crc32 != man->chk->payload_checksum) {
		LOG_ERR("Check flash image payload checksum ...fail.");
		return CPTRA_ERR_PAYLOAD_CHKSUM;
	}

	LOG_INF("Check flash image checksum ...pass.");
#else
	LOG_INF("Check flash image checksum ...bypass.");
#endif

	return CPTRA_SUCCESS;
}

static int cptra_read_header(struct manifest_image_info *man, struct manifest_load_info *info)
{
	void *ptr = NULL;
	struct cptra_manifest_hdr *hdr = NULL;

	ptr = cptra_read(info, sizeof(struct cptra_manifest_hdr));
	if (!ptr) {
		LOG_ERR("Failed to read manifest header.");
		return CPTRA_ERR_READ_HDR;
	}

	hdr = (struct cptra_manifest_hdr *)ptr;
	if (hdr->magic != CPTRA_FLASH_IMG_MAGIC) {
		LOG_ERR("Manifest header magic mismatch: 0x%x.", hdr->magic);
		return CPTRA_ERR_HDR_MAGIC_MISMATCH;
	}

	if (hdr->img_count > CPTRA_IMC_ENTRY_COUNT) {
		LOG_ERR("Manifest image count exceeds maximum limit: %d.", hdr->img_count);
		return CPTRA_ERR_EXCEED_MAX_IMG_COUNT;
	}

	man->hdr = (struct cptra_manifest_hdr *)ptr;

	return CPTRA_SUCCESS;
}

static int cptra_read_checksum(struct manifest_image_info *man, struct manifest_load_info *info)
{
	void *ptr = NULL;

	ptr = cptra_read(info, sizeof(struct cptra_manifest_hdr));
	if (!ptr)
		return CPTRA_ERR_READ_CHKSUM;

	man->chk = (struct cptra_checksum_info *)ptr;

	return CPTRA_SUCCESS;
}

static int cptra_read_img_info(struct manifest_image_info *man, struct manifest_load_info *info)
{
	int img_num = man->hdr->img_count;
	void *ptr = NULL;

	if (img_num > CPTRA_IMC_ENTRY_COUNT)
		return CPTRA_ERR_EXCEED_MAX_IMG_COUNT;

	ptr = cptra_read(info, sizeof(struct cptra_image_info) * img_num);
	if (!ptr)
		return CPTRA_ERR_READ_IMG_INFO;

	man->img_info = (struct cptra_image_info *)ptr;

	return CPTRA_SUCCESS;
}

static int cptra_read_all_image(struct manifest_image_info *man, struct manifest_load_info *info)
{
	int img_size = 0;
	void *ptr = NULL;

	img_size = cptra_get_all_image_size(man);
	if (img_size < 0)
		return CPTRA_ERR_IMAGE_SIZE_OVERFLOW;

	ptr = cptra_read(info, img_size);
	if (!ptr)
		return CPTRA_ERR_READ_FULL_IMG;

	return CPTRA_SUCCESS;
}

static int cptra_simple_manifest_read(struct manifest_image_info *man_info,
				      struct manifest_load_info *info, uint32_t sector)
{
	int ret = 0;

	info->write_sector = 0;
	info->read_sector = sector;

	ret = cptra_read_header(man_info, info);
	if (ret)
		goto fail;

	ret = cptra_read_checksum(man_info, info);
	if (ret)
		goto fail;

	ret = cptra_read_img_info(man_info, info);
	if (ret)
		goto fail;

	ret = cptra_read_all_image(man_info, info);
	if (ret)
		goto fail;

	ret = manifest_crc32_check(man_info, info);
	if (ret)
		goto fail;

	return ret;
fail:
	LOG_ERR("Manifest simple manifeset read fail (0x%x).\n", ret);
	return ret;
}

static int cptra_simple_manifest_parse(struct manifest_image_info *man_info)
{
	struct cptra_soc_manifest *manifest = NULL;

	/* Find the soc manifest */
	manifest = cptra_get_soc_mafniest(man_info);
	if (!manifest)
		return CPTRA_ERR_READ_SOC_MANIFEST;

	if (manifest->preamble.manifest_marker != CPTRA_MBCMD_SET_AUTH_MANIFEST)
		return CPTRA_ERR_SOC_MANIFEST_MAGIC_MISMATCH;

		/* Verify SoC manifest */
#ifdef CONFIG_CPTRA_MANIFEST_SIGNATURE
	if (cptra_verify_soc_manifest(manifest)) {
		LOG_INF("Verify soc manifest... fail");
		return CPTRA_ERR_SOC_MANIFEST_VFY;
	}
#endif

	/* SoC manifest verification pass */
	man_info->soc_manifest = manifest;

	return CPTRA_SUCCESS;
}

static int cptra_simple_manifest_load(struct manifest_image_info *man_info)
{
	void *img_bin = NULL;
	int ret = 0;
	uint32_t img_size = 0;
	struct cptra_soc_manifest *man = man_info->soc_manifest;
	struct cptra_manifest_ime *ime = &man->imc[0];

	for (ime = &man->imc[0]; ime < man->imc + man->ime_count; ime++) {
		/* Check the whether ime denote image should be loaded */
		if (!cptra_ime_loadable_image(ime))
			continue;

		/* Get the ime denoted image and size */
		img_bin = cptra_ime_get_bin(man_info, ime);
		img_size = cptra_ime_image_size(man_info, ime);
		if (!img_bin || img_size < 0)
			return CPTRA_ERR_IMAGE_READ;

			/* Verify the ime denoted image */
#ifdef CONFIG_CPTRA_MANIFEST_SIGNATURE
		ret = cptra_verify_image(img_bin, img_size, ime);
		LOG_INF("Verify %s image... %s", cptra_ime_get_image_name(ime),
			ret ? "fail" : "pass");
		if (ret)
			return ret;
#endif

		/* Load the ime denoted image */
		ret = cptra_ime_load_image(img_bin, img_size, ime);
		LOG_INF("Load %s image... %s", cptra_ime_get_image_name(ime),
			ret ? "fail" : "pass");

		board_manifest_image_post_process(ime);
	}

	return ret;
}

static int cptra_load_simple_manifest(struct manifest_image_info *man_image,
				      struct manifest_load_info *info, uint64_t sector, void *man)
{
	int ret = 0;

	ret = cptra_simple_manifest_read(man_image, info, sector);
	if (ret)
		goto end;

	ret = cptra_simple_manifest_parse(man_image);
	if (ret)
		goto end;

	ret = cptra_simple_manifest_load(man_image);
	if (ret)
		goto end;

end:
	LOG_INF("Caliptra load simple image... %s", ret ? "fail" : "pass");
	return ret;
}

int cptra_load_image(enum boot_mode_type boot_mode, struct manifest_image_info *man_info)
{
	uint32_t blk = 0;
	void *header = NULL;
	struct manifest_load_info load = {0};

	if (!man_info) {
		LOG_ERR("Calitra manifest load fail: unkown error");
		return CPTRA_ERR_INVALID_PARAMETER;
	}

	switch (boot_mode) {
	case BOOT_DEV_SPI:
		LOG_INF("Trying to boot from RAM");
		load.read = fit_ram_load_read;
		header = (void *)CONFIG_SOC_FMC_LOAD_FIT_ADDRESS;
		break;
	default:
		LOG_ERR("Calitra manifest load fail: unsupported boot device");
		return CPTRA_ERR_UNSUPPORT_BOOT_DEV;
	}

	return cptra_load_simple_manifest(man_info, &load, blk, header);
}
