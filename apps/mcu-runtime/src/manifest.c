/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <manifest.h>
#include <platform.h>
#include <spi.h>

#include <zephyr/drivers/cptra.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/crc.h>
#include <ast_loader.h>

LOG_MODULE_REGISTER(cptra_manifest, CONFIG_LOG_DEFAULT_LEVEL);

#include <zephyr/drivers/flash.h>
__weak int ast_loader_read(uint32_t *dst, uint32_t src, uint32_t len)
{
	const struct device *dev = device_get_binding("fmc@0");

	return flash_read(dev, src, dst, len);
}

uint32_t cptra_manifest_start_offset(void)
{
	/* AST2700-A1 */
	if (FIELD_GET(0x000000ff, sys_read32(SCU1_REVISION_ID)) == 3 &&
	    FIELD_GET(0x00ff0000, sys_read32(SCU1_REVISION_ID)) == 1)
		return 0x00100000;

	return 0x0;
}

#ifdef CONFIG_CPTRA_2X_LAYOUT
static uint32_t calc_additive_checksum(const uint8_t *data, size_t length)
{
    uint32_t sum = 0;

    for (size_t i = 0; i < length; i++) {
        sum = sum + data[i];
    }

    return (uint32_t)(0 - sum);
}
#endif

static int cptra_crc32_check(struct cptra_image_context *ctx)
{
#ifdef CONFIG_CRC
	uint32_t hdr_crc32 = 0;

	/* Check the flash image header crc checksum */
#ifndef CONFIG_CPTRA_2X_LAYOUT
	hdr_crc32 = crc32_ieee((uint8_t *)ctx->hdr, sizeof(struct cptra_manifest_hdr));
#else
	hdr_crc32 = calc_additive_checksum((uint8_t *)ctx->hdr, sizeof(struct cptra_manifest_hdr));
#endif
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

static int cptra_read_header(struct cptra_image_context *ctx)
{
	int ret = 0;
	uint32_t manifest_flash_ofst = cptra_manifest_start_offset();
	static struct cptra_manifest_hdr hdr = { 0 };

	/* Read the manfiest header */
	ret = ast_loader_read((uint32_t *)&hdr, manifest_flash_ofst,
			      sizeof(struct cptra_manifest_hdr));
	if (ret) {
		LOG_ERR("Failed to read manifest header.");
		return CPTRA_ERR_READ_HDR;
	}

	if (hdr.magic != CPTRA_FLASH_IMG_MAGIC) {
		LOG_ERR("Manifest header magic mismatch: 0x%x.", hdr.magic);
		return CPTRA_ERR_HDR_MAGIC_MISMATCH;
	}

	if (hdr.img_count > CPTRA_IMC_ENTRY_COUNT) {
		LOG_ERR("Manifest image count exceeds maximum limit: %d.",
			hdr.img_count);
		return CPTRA_ERR_EXCEED_MAX_IMG_COUNT;
	}

	/* The image header is correct, keep it in context */
	ctx->hdr = &hdr;

	return CPTRA_SUCCESS;
}

static int cptra_read_chk_img_info(struct cptra_image_context *ctx)
{
	int ret = 0;
	uint32_t manifest_flash_ofst = cptra_manifest_start_offset();
	int img_num = ctx->hdr->img_count;
	static uint8_t chk_img[sizeof(struct cptra_checksum_info) +
			       sizeof(struct cptra_image_info) *
				       CPTRA_IMC_ENTRY_COUNT] = { 0 };
	uint32_t ofst = sizeof(struct cptra_manifest_hdr);
	uint32_t size = 0;

	if (img_num > CPTRA_IMC_ENTRY_COUNT)
		return CPTRA_ERR_EXCEED_MAX_IMG_COUNT;

	size = sizeof(struct cptra_checksum_info);
	size += sizeof(struct cptra_image_info) * img_num;
	ret = ast_loader_read((uint32_t *)chk_img, manifest_flash_ofst + ofst,
			      size);
	if (ret)
		return CPTRA_ERR_READ_IMG_INFO;

	ctx->chk = (struct cptra_checksum_info *)chk_img;
	ctx->img_info = (struct cptra_image_info *)(chk_img +
					sizeof(struct cptra_checksum_info));

	return CPTRA_SUCCESS;
}

static int cptra_read_abb_header(struct cptra_image_context *ctx)
{
	int ret = 0;

	/* header, checksum, img_info has been read exit directly */
	if (ctx->hdr && ctx->chk && ctx->img_info)
		return ret;

	ret = cptra_read_header(ctx);
	if (ret)
		goto fail;

	ret = cptra_read_chk_img_info(ctx);
	if (ret)
		goto fail;

	ret = cptra_crc32_check(ctx);
	if (ret)
		goto fail;

fail:
	return ret;
}

static int cptra_read_abb_soc_manifest(struct cptra_image_context *ctx)
{
	int ret = 0;
	static struct cptra_soc_manifest soc_manifest;

#ifndef CONFIG_CPTRA_2X_LAYOUT
	if (!(sys_read32(SCU1_REG + SCU1_CPTRA) & SCU1_CPTRA_RDY_FOR_RT)) {
		LOG_WRN("Caliptra is unavailable");
		return CPTRA_SUCCESS;
	}
#endif

	ret = ast_loader_load_image(CPTRA_MANIFEST_FW_ID,
				    (uint32_t *)&soc_manifest, true);
	if (ret)
		return CPTRA_ERR_SOC_MANIFEST_READ_ERROR;

	if (soc_manifest.preamble.manifest_marker != CPTRA_AUTH_MANIFEST_MARKER) {
		LOG_ERR("Soc manifest magic mismatch: 0x%x.",
			soc_manifest.preamble.manifest_marker);
		return CPTRA_ERR_SOC_MANIFEST_MAGIC_MISMATCH;
	}
	ctx->soc_manifest = &soc_manifest;

	LOG_INF("ver: %x, flags: %x, soc_ver: %x",
		soc_manifest.preamble.manifest_version,
		soc_manifest.preamble.manifest_flags,
		soc_manifest.preamble.manifest_sec_version);
	LOG_INF("manfiest vendor pubk: 0x%08x",
		soc_manifest.preamble.manifest_vendor_ecc384_key[0]);
	LOG_INF("manfiest owner pubk: 0x%08x",
		soc_manifest.preamble.manifest_owner_ecc384_key[0]);

	return CPTRA_SUCCESS;
}

static struct cptra_image_context cptra_ctx;
static void cptra_deinit_abb_loader(int ret)
{
	if (ret && cptra_ctx.hdr)
		memset(cptra_ctx.hdr, 0, sizeof(struct cptra_manifest_hdr));

	if (ret && cptra_ctx.chk)
		memset(cptra_ctx.chk, 0, sizeof(struct cptra_checksum_info));

	if (ret && cptra_ctx.img_info)
		memset(cptra_ctx.img_info, 0,
		       sizeof(struct cptra_image_info) * CPTRA_IMC_ENTRY_COUNT);

	if (ret && cptra_ctx.soc_manifest)
		memset(cptra_ctx.soc_manifest, 0,
		       sizeof(struct cptra_soc_manifest));

	__ASSERT(!ret, "Caliptra load image fail, ret: 0x%x", ret);
}

static int cptra_init_abb_loader(void)
{
	int ret = 0;

	if (cptra_ctx.hdr && cptra_ctx.img_info && cptra_ctx.chk)
		return ret;

	ret = cptra_read_abb_header(&cptra_ctx);
	LOG_INF("Read abb header... %s (0x%x)", ret ? "fail" : "pass", ret);

	cptra_deinit_abb_loader(ret);
	return ret;
}

int cptra_verify_abb_loader(void)
{
	int ret = 0;

	if (cptra_ctx.soc_manifest)
		return ret;

	ret = cptra_read_abb_soc_manifest(&cptra_ctx);
	LOG_INF("Read soc manifest... %s (0x%x)", ret ? "fail" : "pass", ret);

	cptra_deinit_abb_loader(ret);
	return ret;
}

int cptra_load_abb_image(void)
{
	int ret = 0;
	uint32_t *load_addr = 0;
	struct cptra_soc_manifest *man = cptra_ctx.soc_manifest;
	struct cptra_image_info *img_info = cptra_ctx.img_info;
	uint32_t image_count = cptra_ctx.hdr->img_count;
	struct cptra_manifest_ime *ime = NULL;
	uint32_t fw_id;
	uint32_t identifier;
	uint32_t i;

	if (img_info == NULL)
		return CPTRA_ERR_ABB_LOADER_NOT_READY;

	for (i = 0; i < image_count && !ret; i++) {
		identifier = img_info[i].identifier;
		if (identifier <= CPTRA_FMC_HDR_ID) {
			continue;
		}

		if (!cptra_find_fw_id_by_identifier(identifier, &fw_id))
			continue;

		/* Check the whether ime denote image should be loaded */
		/* if ime is NULL, then no check */
		ime = cptra_get_ime_by_fw_id(man, fw_id);
		if (!cptra_ime_loadable_image(ime))
			continue;

		load_addr = (uint32_t *)cptra_ime_get_load_addr(fw_id);
		if (!load_addr)
			continue;

		ret = ast_loader_load_manifest_image(fw_id, load_addr, true);
		LOG_INF("Load %s image... %s (0x%x)", cptra_ime_get_image_name(fw_id),
			ret ? "fail" : "pass", ret);

		if (!ret)
			board_manifest_image_post_process(fw_id);
	}

	cptra_deinit_abb_loader(ret);
	return ret;
}

int cptra_get_abb_imginfo(uint32_t fw_id, uint32_t *ofst, uint32_t *size)
{
	int ret = 0;
	int image_offset = 0;
	int image_size = 0;

	ret = cptra_init_abb_loader();
	if (ret)
		return ret;

	image_offset = cptra_ime_image_offset(&cptra_ctx, fw_id);
	if (image_offset < 0)
		return CPTRA_ERR_IMAGE_READ;

	image_size = cptra_ime_image_size(&cptra_ctx, fw_id);
	if (image_size < 0)
		return CPTRA_ERR_IMAGE_READ;

	*ofst = image_offset;
	*size = image_size;

	return CPTRA_SUCCESS;
}
