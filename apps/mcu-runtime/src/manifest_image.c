/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <manifest.h>
#include <stdint.h>

#include <zephyr/drivers/cptra.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(cptra_manifest_image, CONFIG_LOG_DEFAULT_LEVEL);

/* Define caliptra image load address */
#define CPTRA_NO_LOAD_ADDR    (0x00000000)
#define CPTRA_FMC_LOAD_ADDR   (CONFIG_FMC_LOAD_ADDR)
#define CPTRA_ATF_LOAD_ADDR   (CONFIG_ATF_LOAD_ADDR)
#define CPTRA_OPTEE_LOAD_ADDR (CONFIG_OPTEE_LOAD_ADDR)
#define CPTRA_UBOOT_LOAD_ADDR (CONFIG_UBOOT_LOAD_ADDR)
#define CPTRA_SSP_LOAD_ADDR   (CONFIG_SSP_LOAD_ADDR)
#define CPTRA_TSP_LOAD_ADDR   (CONFIG_TSP_LOAD_ADDR)

/* Define caliptra image loadable property */
#define CPTRA_LOADABLE_MASK GENMASK(31, 30)
#define CPTRA_BOOTMCU_LOADABLE (1)
#define CPTRA_SSP_LOADABLE (2)

struct cptra_load_image {
	char *name;
	uint32_t identifier;
	uint32_t fw_id;
	uintptr_t load_addr;
};

static struct cptra_load_image image_list[] = {
	{ "manifest", CPTRA_SOC_MANIFEST_HDR_ID, CPTRA_MANIFEST_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "mcu_fmc", CPTRA_FMC_HDR_ID, CPTRA_FMC_FW_ID, CPTRA_FMC_LOAD_ADDR},
	{ "ddr4_imem", CPTRA_DDR4_IMEM_HDR_ID, CPTRA_DDR4_IMEM_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "ddr4_dmem", CPTRA_DDR4_DMEM_HDR_ID, CPTRA_DDR4_DMEM_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "ddr4_2d_imem", CPTRA_DDR4_2D_IMEM_HDR_ID, CPTRA_DDR4_2D_IMEM_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "ddr4_2d_dmem", CPTRA_DDR4_2D_DMEM_HDR_ID, CPTRA_DDR4_2D_DMEM_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "ddr5_imem", CPTRA_DDR5_IMEM_HDR_ID, CPTRA_DDR5_IMEM_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "ddr5_dmem", CPTRA_DDR5_DMEM_HDR_ID, CPTRA_DDR5_DMEM_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "dp_fw", CPTRA_DP_FW_HDR_ID, CPTRA_DP_FW_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "uefi", CPTRA_UEFI_HDR_ID, CPTRA_UEFI_FW_ID, CPTRA_NO_LOAD_ADDR},
	{ "atf", CPTRA_ATF_HDR_ID, CPTRA_ATF_FW_ID, CPTRA_ATF_LOAD_ADDR},
	{ "optee", CPTRA_OPTEE_HDR_ID, CPTRA_OPTEE_FW_ID, CPTRA_OPTEE_LOAD_ADDR},
	{ "uboot", CPTRA_UBOOT_HDR_ID, CPTRA_UBOOT_FW_ID, CPTRA_UBOOT_LOAD_ADDR},
	{ "ssp", CPTRA_SSP_HDR_ID, CPTRA_SSP_FW_ID, CPTRA_SSP_LOAD_ADDR},
	{ "tsp", CPTRA_TSP_HDR_ID, CPTRA_TSP_FW_ID, CPTRA_TSP_LOAD_ADDR},
};

static struct cptra_image_info *cptra_find_image_info(struct cptra_image_context *ctx,
						      uint32_t identifier)
{
	bool match = false;
	uint32_t img_num = ctx->hdr->img_count;
	struct cptra_image_info *img_info = ctx->img_info;

	if (img_num > CPTRA_IMC_ENTRY_COUNT + 2)
		return NULL;

	for (img_info = ctx->img_info; img_info < ctx->img_info + img_num; img_info++) {
		if (img_info->identifier == identifier) {
			match = true;
			break;
		}
	}

	return match ? img_info : NULL;
}

static int cptra_img_info_get_offset(struct cptra_image_context *ctx, uint32_t identifier)
{
	struct cptra_image_info *img_info = NULL;

	img_info = cptra_find_image_info(ctx, identifier);

	return img_info ? img_info->offset : CPTRA_ERR_IMAGE_OFFSET_INVALID;
}

static int cptra_img_info_get_size(struct cptra_image_context *ctx, uint32_t identifier)
{
	struct cptra_image_info *img_info = NULL;

	img_info = cptra_find_image_info(ctx, identifier);

	return img_info ? img_info->size : CPTRA_ERR_IMAGE_SIZE_INVALID;
}

static struct cptra_load_image *cptra_find_load_image(uint32_t fw_id)
{
	int i = 0;
	int match = -1;

	for (i = 0; i < ARRAY_SIZE(image_list) && match == -1; i++)
		match = image_list[i].fw_id == fw_id ? i : match;

	return match != -1 ? &image_list[match] : NULL;
}

bool cptra_find_fw_id_by_identifier(uint32_t identifier, uint32_t *fw_id)
{
	int i = 0;

	if(fw_id == NULL)
		return false;

	for (i = 0; i < ARRAY_SIZE(image_list); i++) {
		if (image_list[i].identifier == identifier) {
			*fw_id = image_list[i].fw_id;
			return true;
		}
	}

	return false;
}


bool cptra_ime_loadable_image(struct cptra_manifest_ime *ime)
{
	if (!ime) {
		LOG_WRN("IME is NULL, skip loadable check.");
		return true;
	}
#ifdef CONFIG_CPTRA_2X_LAYOUT
	if (ime->fw_id == CPTRA_ATF_HDR_ID ||
		ime->fw_id == CPTRA_OPTEE_HDR_ID ||
		ime->fw_id == CPTRA_UBOOT_HDR_ID ||
		ime->fw_id == CPTRA_SSP_HDR_ID ||
		ime->fw_id == CPTRA_TSP_HDR_ID)
		return true;
#else
	if (FIELD_GET(CPTRA_LOADABLE_MASK, ime->flags) == CPTRA_BOOTMCU_LOADABLE)
		return true;
#endif

	return false;
}

int cptra_ime_image_offset(struct cptra_image_context *ctx, uint32_t fw_id)
{
	struct cptra_load_image *img = NULL;

	if (!ctx)
		return CPTRA_ERR_IMAGE_OFFSET_INVALID;

	img = cptra_find_load_image(fw_id);
	if (!img) {
		LOG_ERR("Cannot find image with fw_id 0x%x.", fw_id);
		return CPTRA_ERR_IMAGE_OFFSET_INVALID;
	}

	return cptra_img_info_get_offset(ctx, img->identifier);
}

char *cptra_ime_get_image_name(uint32_t fw_id)
{
	struct cptra_load_image *img = NULL;

	img = cptra_find_load_image(fw_id);

	return img ? img->name : "Unknown";
}

int cptra_ime_image_size(struct cptra_image_context *ctx, uint32_t fw_id)
{
	struct cptra_load_image *img = NULL;

	if (!ctx)
		return CPTRA_ERR_IMAGE_SIZE_INVALID;

	img = cptra_find_load_image(fw_id);
	if (!img) {
		LOG_ERR("Cannot find image with fw_id 0x%x.", fw_id);
		return CPTRA_ERR_IMAGE_SIZE_INVALID;
	}

	return cptra_img_info_get_size(ctx, img->identifier);
}

uintptr_t cptra_ime_get_load_addr(uint32_t fw_id)
{
	struct cptra_load_image *img = NULL;

	img = cptra_find_load_image(fw_id);
	if (!img) {
		LOG_ERR("Cannot find image with fw_id 0x%x.", fw_id);
		return (uintptr_t)NULL;
	}

	return img->load_addr;
}

struct cptra_manifest_ime *cptra_get_ime_by_fw_id(struct cptra_soc_manifest *man,
						  uint32_t fw_id)
{
	struct cptra_manifest_ime *ime = NULL;
	struct cptra_load_image *img = NULL;
	uint32_t i;

	if (!man)
		return NULL;

	img = cptra_find_load_image(fw_id);
	if (!img) {
		LOG_ERR("Cannot find image with fw_id 0x%x.", fw_id);
		return (uintptr_t)NULL;
	}

	for (i = 0;	 i < man->ime_count; i++) {
		ime = &man->imc[i];
#ifndef CONFIG_CPTRA_2X_LAYOUT
		if (ime->fw_id == img->fw_id)
#else
		if (ime->fw_id == img->identifier)
#endif
			return ime;
	}
	return NULL;
}
