/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <manifest.h>
#include <stdint.h>

#include <zephyr/drivers/cptra.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(cptra_manifest_image, CONFIG_LOG_DEFAULT_LEVEL);

/* Define caliptra image identifier */
#define CPTRA_SOC_MANIFEST_HDR_ID (0x0002)
#define CPTRA_FMC_HDR_ID          (0x0003)
#define CPTRA_ATF_HDR_ID          (0x1000)
#define CPTRA_OPTEE_HDR_ID        (0x1001)
#define CPTRA_UBOOT_HDR_ID        (0x1002)
#define CPTRA_SSP_HDR_ID          (0x1003)

/* Define caliptra image load address */
#define CPTRA_FMC_LOAD_ADDR   (0x00000000)
#define CPTRA_ATF_LOAD_ADDR   (0xb0000000)
#define CPTRA_OPTEE_LOAD_ADDR (0xb0080000)
#define CPTRA_UBOOT_LOAD_ADDR (0x80000000)
#define CPTRA_SSP_LOAD_ADDR   (0xac000000)

/* Define caliptra image loadable property */
#define CPTRA_UNLOADABLE (0)
#define CPTRA_LOADABLE   (1)

struct cptra_load_image {
	char *name;
	uint32_t identifier;
	uint32_t fw_id;
	uintptr_t load_addr;
	bool loadable;
};

static struct cptra_load_image image_list[] = {
	{"mcu_fmc", CPTRA_FMC_HDR_ID, CPTRA_FMC_FW_ID, CPTRA_FMC_LOAD_ADDR, CPTRA_UNLOADABLE},
	{"atf", CPTRA_ATF_HDR_ID, CPTRA_ATF_FW_ID, CPTRA_ATF_LOAD_ADDR, CPTRA_LOADABLE},
	{"optee", CPTRA_OPTEE_HDR_ID, CPTRA_OPTEE_FW_ID, CPTRA_OPTEE_LOAD_ADDR, CPTRA_LOADABLE},
	{"uboot", CPTRA_UBOOT_HDR_ID, CPTRA_UBOOT_FW_ID, CPTRA_UBOOT_LOAD_ADDR, CPTRA_LOADABLE},
	{"ssp", CPTRA_SSP_HDR_ID, CPTRA_SSP_FW_ID, CPTRA_SSP_LOAD_ADDR, CPTRA_LOADABLE},
};

int cptra_get_all_image_size(struct manifest_image_info *man)
{
	int64_t img_size = 0;
	uint32_t img_num = man->hdr->img_count;
	struct cptra_image_info *img_info = man->img_info;

	for (img_info = man->img_info; img_info < man->img_info + img_num; img_info++)
		img_size += img_info->size;

	if (img_size > INT32_MAX)
		LOG_ERR("Total image size is large than UINT32_MAX.");

	return img_size < INT32_MAX ? img_size : CPTRA_ERR_IMAGE_SIZE_OVERFLOW;
}

static struct cptra_image_info *cptra_find_image_info(struct manifest_image_info *man,
						      uint32_t identifier)
{
	bool match = false;
	uint32_t img_num = man->hdr->img_count;
	struct cptra_image_info *img_info = man->img_info;

	for (img_info = man->img_info; img_info < man->img_info + img_num; img_info++) {
		if (img_info->identifier == identifier) {
			match = true;
			break;
		}
	}

	return match ? img_info : NULL;
}

static int cptra_img_info_get_offset(struct manifest_image_info *man, uint32_t identifier)
{
	struct cptra_image_info *img_info = NULL;

	img_info = cptra_find_image_info(man, identifier);

	return img_info ? img_info->offset : CPTRA_ERR_IMAGE_OFFSET_INVALID;
}

static int cptra_img_info_get_size(struct manifest_image_info *man, uint32_t identifier)
{
	struct cptra_image_info *img_info = NULL;

	img_info = cptra_find_image_info(man, identifier);

	return img_info ? img_info->size : CPTRA_ERR_IMAGE_SIZE_INVALID;
}

static void *cptra_img_info_get_bin(struct manifest_image_info *man, uint32_t identifier)
{
	int offset = cptra_img_info_get_offset(man, identifier);

	if (offset < 0) {
		LOG_ERR("Cannot find image with id 0x%x (%x).", identifier, offset);
		return NULL;
	}

	return (void *)(cptra_manifest_buffer_addr(offset));
}

static struct cptra_load_image *cptra_find_load_image(uint32_t fw_id)
{
	int i = 0;
	int match = -1;

	for (i = 0; i < ARRAY_SIZE(image_list) && match == -1; i++)
		match = image_list[i].fw_id == fw_id ? i : match;

	return match != -1 ? &image_list[match] : NULL;
}

void *cptra_get_soc_mafniest(struct manifest_image_info *man)
{
	return cptra_img_info_get_bin(man, CPTRA_SOC_MANIFEST_HDR_ID);
}

void *cptra_ime_get_bin(struct manifest_image_info *man, struct cptra_manifest_ime *ime)
{
	struct cptra_load_image *img = NULL;

	img = cptra_find_load_image(ime->fw_id);
	if (!img) {
		LOG_ERR("Cannot find image with fw_id 0x%x.", ime->fw_id);
		return NULL;
	}

	return cptra_img_info_get_bin(man, img->identifier);
}

int cptra_ime_image_size(struct manifest_image_info *man, struct cptra_manifest_ime *ime)
{
	struct cptra_load_image *img = NULL;

	img = cptra_find_load_image(ime->fw_id);
	if (!img) {
		LOG_ERR("Cannot find image with fw_id 0x%x.", ime->fw_id);
		return CPTRA_ERR_IMAGE_SIZE_INVALID;
	}

	return cptra_img_info_get_size(man, img->identifier);
}

char *cptra_ime_get_image_name(struct cptra_manifest_ime *ime)
{
	struct cptra_load_image *img = NULL;

	img = cptra_find_load_image(ime->fw_id);

	return img ? img->name : "Unknown";
}

bool cptra_ime_loadable_image(struct cptra_manifest_ime *ime)
{
	struct cptra_load_image *img = NULL;

	img = cptra_find_load_image(ime->fw_id);

	return img ? img->loadable : false;
}

uintptr_t cptra_ime_get_load_addr(struct cptra_manifest_ime *ime)
{
	struct cptra_load_image *img = NULL;

	img = cptra_find_load_image(ime->fw_id);
	if (!img) {
		LOG_ERR("Cannot find image with fw_id 0x%x.", ime->fw_id);
		return (uintptr_t)NULL;
	}

	return img->load_addr;
}

int cptra_ime_load_image(void *img_bin, uint32_t img_size, struct cptra_manifest_ime *ime)
{
	uintptr_t load_addr = cptra_ime_get_load_addr(ime);

	if (!load_addr) {
		LOG_ERR("Cannot find load address for fw_id 0x%x.", ime->fw_id);
		return CPTRA_ERR_IMAGE_LOAD;
	}

	memcpy((void *)load_addr, img_bin, img_size);

	return CPTRA_SUCCESS;
}
