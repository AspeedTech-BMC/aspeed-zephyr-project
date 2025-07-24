/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <fit.h>
#include <manifest.h>
#include <platform.h>
#include <scu_ast2700.h>
#include <spi.h>

#include <zephyr/drivers/cptra.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/crc.h>

LOG_MODULE_REGISTER(cptra_manifest, CONFIG_LOG_DEFAULT_LEVEL);

static bool cptra_manifest_sec_en(void)
{
#ifdef CONFIG_CPTRA_MANIFEST_SIGNATURE
	return !!(sys_read32(SCU1_HWSTRAP1) & SCU1_HWSTRAP1_EN_SECBOOT);
#else
	return false;
#endif
}

static void *cptra_read(struct cptra_load_info *info, int size, bool persist)
{
	int count = 0;
	void *buf = cptra_manifest_buffer_addr(info->write_sector);
	void *buf_end = (void *)((uint8_t *)buf + size);

	if (buf < CPTRA_SYS_LOAD_ADDR || buf_end >= CPTRA_SYS_LOAD_ADDR_END)
		return NULL;

	count = info->read((struct fit_load_info *)info, info->read_sector, size, buf);
	if (count <= 0)
		return NULL;

	if (count != size)
		return NULL;

	if (persist) {
		info->read_sector += count;
		info->write_sector += count;
	}

	info->size = persist ? 0 : size;

	return buf;
}

static void cptra_manifest_err_handler(int ret, struct cptra_load_info *info)
{
	uint32_t wipe_size = 0;
	void *buf = cptra_manifest_buffer_addr(0);

	wipe_size = info->write_sector + info->size;
	wipe_size = wipe_size < CPTRA_SYS_LOAD_SIZE ? wipe_size : CPTRA_SYS_LOAD_SIZE;

	if (!ret) {
		LOG_INF("Caliptra load simple image... pass");
	} else {
		/* Wipe the tmp buffer stored image */
		memset(buf, 0, wipe_size);
		LOG_ERR("Caliptra load simple image... fail(%d)", ret);
	}

	__ASSERT(!ret, "Caliptra load simple image fail, ret: %d", ret);
}

static int cptra_crc32_check(struct cptra_image_context *ctx, struct cptra_load_info *info)
{
#ifdef CONFIG_CRC
	uint32_t hdr_crc32 = 0;

	/* Check the flash image header crc checksum */
	hdr_crc32 = crc32_ieee((uint8_t *)ctx->hdr, sizeof(struct cptra_manifest_hdr));
	if (hdr_crc32 != ctx->chk->hdr_checksum) {
		LOG_ERR("Check flash image header checksum ...fail.");
		return CPTRA_ERR_HDR_CHKSUM;
	}

	LOG_INF("Check flash image checksum ...pass.");
#else
	LOG_INF("Check flash image checksum ...bypass.");
#endif

	return CPTRA_SUCCESS;
}

static int cptra_read_header(struct cptra_image_context *ctx, struct cptra_load_info *info)
{
	void *ptr = NULL;
	struct cptra_manifest_hdr *hdr = NULL;

	ptr = cptra_read(info, sizeof(struct cptra_manifest_hdr), true);
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

	ctx->hdr = (struct cptra_manifest_hdr *)ptr;

	return CPTRA_SUCCESS;
}

static int cptra_read_checksum(struct cptra_image_context *ctx, struct cptra_load_info *info)
{
	void *ptr = NULL;

	ptr = cptra_read(info, sizeof(struct cptra_manifest_hdr), true);
	if (!ptr)
		return CPTRA_ERR_READ_CHKSUM;

	ctx->chk = (struct cptra_checksum_info *)ptr;

	return CPTRA_SUCCESS;
}

static int cptra_read_img_info(struct cptra_image_context *ctx, struct cptra_load_info *info)
{
	int img_num = ctx->hdr->img_count;
	void *ptr = NULL;

	if (img_num > CPTRA_IMC_ENTRY_COUNT)
		return CPTRA_ERR_EXCEED_MAX_IMG_COUNT;

	ptr = cptra_read(info, sizeof(struct cptra_image_info) * img_num, true);
	if (!ptr)
		return CPTRA_ERR_READ_IMG_INFO;

	ctx->img_info = (struct cptra_image_info *)ptr;

	return CPTRA_SUCCESS;
}

static int cptra_read_soc_manifest(struct cptra_image_context *ctx, struct cptra_load_info *info,
				   struct cptra_soc_manifest **manifest)
{
	int image_offset = 0;
	struct cptra_soc_manifest *ptr = NULL;

	image_offset = cptra_soc_manifest_offset(ctx);
	if (image_offset < 0)
		return CPTRA_ERR_SOC_MANIFEST_NO_INFO;

	info->read_sector = image_offset;
	ptr = cptra_read(info, sizeof(struct cptra_soc_manifest), true);
	if (!ptr)
		return CPTRA_ERR_SOC_MANIFEST_READ_ERROR;

	if (ptr->preamble.manifest_marker != CPTRA_MBCMD_SET_AUTH_MANIFEST)
		return CPTRA_ERR_SOC_MANIFEST_MAGIC_MISMATCH;

	*manifest = ptr;

	LOG_INF("ver: %x, flags: %x, soc_ver: %x", ptr->preamble.manifest_version,
		ptr->preamble.manifest_flags, ptr->preamble.manifest_sec_version);
	LOG_INF("manfiest vendor pubk: 0x%08x", ptr->preamble.manifest_vendor_ecc384_key[0]);
	LOG_INF("manfiest owner pubk: 0x%08x", ptr->preamble.manifest_owner_ecc384_key[0]);

	return CPTRA_SUCCESS;
}

static void *cptra_read_image(struct cptra_image_context *ctx, struct cptra_load_info *info,
			      struct cptra_manifest_ime *ime)
{
	int image_offset = 0;
	int image_size = 0;
	void *ptr = NULL;

	image_offset = cptra_ime_image_offset(ctx, ime);
	if (image_offset < 0)
		goto end;

	image_size = cptra_ime_image_size(ctx, ime);
	if (image_size < 0)
		goto end;

	info->read_sector = image_offset;
	ptr = cptra_read(info, image_size, false);
	if (!ptr)
		goto end;

end:
	return ptr;
}

static int cptra_simple_manifest_read(struct cptra_image_context *ctx, struct cptra_load_info *info,
				      uint32_t sector)
{
	int ret = 0;

	info->write_sector = 0;
	info->read_sector = sector;

	ret = cptra_read_header(ctx, info);
	if (ret)
		goto fail;

	ret = cptra_read_checksum(ctx, info);
	if (ret)
		goto fail;

	ret = cptra_read_img_info(ctx, info);
	if (ret)
		goto fail;

	ret = cptra_crc32_check(ctx, info);
	if (ret)
		goto fail;

	return ret;
fail:
	LOG_ERR("Manifest simple manifeset read fail (0x%x).\n", ret);
	return ret;
}

static int cptra_simple_manifest_parse(struct cptra_image_context *ctx,
				       struct cptra_load_info *info)
{
	int ret = 0;
	struct cptra_soc_manifest *manifest = NULL;

	/* Find the soc manifest */
	ret = cptra_read_soc_manifest(ctx, info, &manifest);
	if (!manifest || ret)
		return ret;

	/* Verify SoC manifest */
	if (cptra_manifest_sec_en()) {
		if (cptra_verify_soc_manifest(manifest)) {
			LOG_INF("Verify soc manifest... fail");
			return CPTRA_ERR_SOC_MANIFEST_VFY;
		}

		ret = cptra_verify_soc_manifest_ver(manifest);
		if (ret) {
			LOG_INF("Verify soc manifest version... fail");
			return ret;
		}
	}

	/* SoC manifest verification pass */
	ctx->soc_manifest = manifest;

	return CPTRA_SUCCESS;
}

static int cptra_simple_manifest_load(struct cptra_image_context *ctx, struct cptra_load_info *info)
{
	void *img_bin = NULL;
	int ret = 0;
	uint32_t img_size = 0;
	struct cptra_soc_manifest *man = ctx->soc_manifest;
	struct cptra_manifest_ime *ime = &man->imc[0];

	for (ime = &man->imc[0]; ime < man->imc + man->ime_count; ime++) {
		/* Check the whether ime denote image should be loaded */
		if (!cptra_ime_loadable_image(ime))
			continue;

		/* Get the ime denoted image and size */
		img_bin = cptra_read_image(ctx, info, ime);
		img_size = cptra_ime_image_size(ctx, ime);
		if (!img_bin || img_size < 0)
			return CPTRA_ERR_IMAGE_READ;

		/* Verify the ime denoted image */
		if (cptra_manifest_sec_en()) {
			ret = cptra_verify_image(img_bin, img_size, ime);
			LOG_INF("Verify %s image... %s", cptra_ime_get_image_name(ime),
				ret ? "fail" : "pass");
			if (ret)
				return ret;
		}

		/* Load the ime denoted image */
		ret = cptra_ime_load_image(img_bin, img_size, ime);
		LOG_INF("Load %s image... %s", cptra_ime_get_image_name(ime),
			ret ? "fail" : "pass");

		board_manifest_image_post_process(ime);
	}

	return ret;
}

static int cptra_load_simple_manifest(struct cptra_image_context *ctx, struct cptra_load_info *info,
				      uint64_t sector, void *man)
{
	int ret = 0;

	ret = cptra_simple_manifest_read(ctx, info, sector);
	if (ret)
		goto end;

	ret = cptra_simple_manifest_parse(ctx, info);
	if (ret)
		goto end;

	ret = cptra_simple_manifest_load(ctx, info);
	if (ret)
		goto end;

end:
	cptra_manifest_err_handler(ret, info);
	return ret;
}

int cptra_load_image(enum boot_mode_type boot_mode, struct cptra_image_context *ctx)
{
	uint32_t blk = 0;
	void *header = NULL;
	struct cptra_load_info load = {0};

	if (!ctx) {
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

	return cptra_load_simple_manifest(ctx, &load, blk, header);
}
