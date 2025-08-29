/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <manifest.h>
#include <platform.h>
#include <scu_ast2700.h>
#include <spi.h>

#include <zephyr/drivers/cptra.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/crc.h>
#include <ast_loader.h>

LOG_MODULE_REGISTER(cptra_manifest, CONFIG_LOG_DEFAULT_LEVEL);

struct cptra_manifest_hdr manihdr;

static uint8_t sram_buf[CPTRA_SRAM_BUF_SIZE];
static struct cptra_image_context cptra_ctx;

static bool cptra_manifest_sec_en(void)
{
#ifdef CONFIG_CPTRA_MANIFEST_SIGNATURE
	return true;
#else
	return false;
#endif
}

#include <zephyr/drivers/flash.h>
__weak int ast_loader_read(uint32_t *dst, uint32_t src, uint32_t len)
{
	const struct device *dev = device_get_binding("fmc@0");

	return flash_read(dev, src, dst, len);
}

static void *cptra_read(struct cptra_load_info *loader, int size, bool persist)
{
	int ret = 0;
	uintptr_t src = CPTRA_MANIFEST_OFFSET + loader->read_sector;
	uintptr_t dest = loader->base + loader->write_sector;

	if (dest < loader->base || dest >= loader->limit)
		return NULL;

	ret = ast_loader_read((uint32_t *)dest, src, size);
	if (ret)
		return NULL;

	if (persist) {
		loader->read_sector += size;
		loader->write_sector += size;
	}

	loader->size = persist ? 0 : size;

	return (void *)dest;
}

static void cptra_manifest_err_handler(int ret, struct cptra_load_info *loader)
{
	uint32_t wipe_size = 0;

	if (ret) {
		/* Wipe the sram tmp buffer stored image */
		wipe_size = loader->write_sector + loader->size;
		wipe_size = wipe_size < loader->limit ? wipe_size : loader->limit;
		memset((void *)loader->base, 0, wipe_size);

		LOG_ERR("Caliptra load simple image... fail(0x%x)", ret);
	}

	__ASSERT(!ret, "Caliptra load simple image fail, ret: 0x%x", ret);
}

static int cptra_crc32_check(struct cptra_image_context *ctx)
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

static int cptra_read_header(struct cptra_image_context *ctx, struct cptra_load_info *loader)
{
	void *ptr = NULL;
	struct cptra_manifest_hdr *hdr = NULL;

	loader->read_sector = 0;
	ptr = cptra_read(loader, sizeof(struct cptra_manifest_hdr), true);
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

static int cptra_read_header_body(struct cptra_image_context *ctx, struct cptra_load_info *loader)
{
	int img_num = ctx->hdr->img_count;
	uint32_t chk_sz = 0;
	uint32_t info_sz = 0;
	void *ptr = NULL;

	if (img_num > CPTRA_IMC_ENTRY_COUNT)
		return CPTRA_ERR_EXCEED_MAX_IMG_COUNT;

	loader->read_sector = sizeof(struct cptra_manifest_hdr);
	chk_sz = sizeof(struct cptra_checksum_info);
	info_sz = sizeof(struct cptra_image_info) * img_num;
	ptr = cptra_read(loader, chk_sz + info_sz, true);
	if (!ptr)
		return CPTRA_ERR_READ_IMG_INFO;

	ctx->chk = (struct cptra_checksum_info *)ptr;
	ctx->img_info = (struct cptra_image_info *)((uint8_t *)ptr + chk_sz);

	return CPTRA_SUCCESS;
}

static int cptra_read_soc_manifest(struct cptra_image_context *ctx, struct cptra_load_info *loader,
				   struct cptra_soc_manifest **manifest)
{
	int image_offset = 0;
	struct cptra_soc_manifest *ptr = NULL;

	image_offset = cptra_soc_manifest_offset(ctx);
	if (image_offset < 0)
		return CPTRA_ERR_SOC_MANIFEST_NO_INFO;

	loader->read_sector = image_offset;
	ptr = cptra_read(loader, sizeof(struct cptra_soc_manifest), true);
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

static void *cptra_read_image(struct cptra_image_context *ctx, struct cptra_load_info *loader,
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

	loader->read_sector = image_offset;
	ptr = cptra_read(loader, image_size, false);
	if (!ptr)
		goto end;

end:
	return ptr;
}

static int cptra_simple_manifest_read(struct cptra_image_context *ctx,
				      struct cptra_load_info *loader)
{
	int ret = 0;

	/* header, checksum, img_info has been read exit directly */
	if (ctx->hdr && ctx->chk && ctx->img_info)
		return ret;

	ret = cptra_read_header(ctx, loader);
	if (ret)
		goto fail;

	ret = cptra_read_header_body(ctx, loader);
	if (ret)
		goto fail;

	ret = cptra_crc32_check(ctx);
	if (ret)
		goto fail;

	LOG_INF("Manifest simple manifeset read success.\n");
	return ret;
fail:
	LOG_ERR("Manifest simple manifeset read fail (0x%x).\n", ret);
	return ret;
}

static int cptra_simple_manifest_parse(struct cptra_image_context *ctx,
				       struct cptra_load_info *loader)
{
	int ret = 0;
	struct cptra_soc_manifest *manifest = NULL;

	/* soc manifest has been read, exit directly */
	if (ctx->soc_manifest)
		return ret;

	/* Find the soc manifest */
	ret = cptra_read_soc_manifest(ctx, loader, &manifest);
	if (!manifest || ret)
		return ret;

	/* Verify SoC manifest */
	if (cptra_manifest_sec_en()) {
		if (cptra_verify_soc_manifest(manifest)) {
			LOG_ERR("Verify soc manifest... fail");
			return CPTRA_ERR_SOC_MANIFEST_VFY;
		}

		ret = cptra_verify_soc_manifest_ver(manifest);
		if (ret) {
			LOG_ERR("Verify soc manifest version... fail");
			return ret;
		}
	}

	/* SoC manifest verification pass */
	ctx->soc_manifest = manifest;

	LOG_INF("Manifest soc manifeset read success.\n");
	return CPTRA_SUCCESS;
}

static int cptra_simple_manifest_load(struct cptra_image_context *ctx,
				      struct cptra_load_info *loader)
{
	void *img_bin = NULL;
	int ret = 0;
	uint32_t img_size = 0;
	struct cptra_soc_manifest *man = ctx->soc_manifest;
	struct cptra_manifest_ime *ime = &man->imc[0];

	for (ime = &man->imc[0]; ime < man->imc + man->ime_count; ime++) {
		/* Check the whether ime denote image should be loaded */
		if (!cptra_ime_loadable_image(ctx, ime))
			continue;

		/* Get the ime denoted image and size */
		img_bin = cptra_read_image(ctx, loader, ime);
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

static int cptra_load_simple_manifest(struct cptra_image_context *ctx)
{
	int ret = 0;
	struct cptra_load_info sram = {0};

	CPTRA_INIT_LOADER(&sram, sram_buf, sizeof(sram_buf));

	ret = cptra_simple_manifest_read(ctx, &sram);
	if (ret)
		goto end;

	ret = cptra_simple_manifest_parse(ctx, &sram);
	if (ret)
		goto end;

end:
	cptra_manifest_err_handler(ret, &sram);
	return ret;
}

static int cptra_load_simple_manifest_image(struct cptra_image_context *ctx)
{
	int ret = 0;
	struct cptra_load_info dram = {0};

	CPTRA_INIT_LOADER(&dram, CPTRA_SYS_LOAD_ADDR, CPTRA_SYS_LOAD_SIZE);
	ret = cptra_simple_manifest_load(ctx, &dram);

	cptra_manifest_err_handler(ret, &dram);
	return ret;
}

int cptra_load_image(void)
{
	int ret = 0;

	ret = cptra_load_simple_manifest(&cptra_ctx);
	if (ret)
		return ret;

	return cptra_load_simple_manifest_image(&cptra_ctx);
}

int cptra_hdr_get_prebuilt(uint32_t fw_id, uint32_t *ofst, uint32_t *size)
{
	int image_offset = 0;
	int image_size = 0;
	int ret = 0;
	struct cptra_manifest_ime ime = {.fw_id = fw_id};

	ret = cptra_load_simple_manifest(&cptra_ctx);
	if (ret)
		return ret;

	image_offset = cptra_ime_image_offset(&cptra_ctx, &ime);
	if (image_offset < 0)
		return CPTRA_ERR_IMAGE_READ;

	image_size = cptra_ime_image_size(&cptra_ctx, &ime);
	if (image_size < 0)
		return CPTRA_ERR_IMAGE_READ;

	*ofst = image_offset;
	*size = image_size;

	return CPTRA_SUCCESS;
}
