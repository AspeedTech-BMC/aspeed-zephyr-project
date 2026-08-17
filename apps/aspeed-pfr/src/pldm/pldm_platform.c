/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/sha512.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/util.h>

#include "pldm.h"
#include "pldm_flsh.h"

LOG_MODULE_REGISTER(pfr_pldm_update, CONFIG_LOG_DEFAULT_LEVEL);

#define PFR_FLSH_COMPONENT_ID 0x1080
#define PFR_CM4_COMPONENT_ID 0x100e
#define PFR_PLDM_MIN_TRANSFER_SIZE 32
#define PFR_FLASH_IO_CHUNK (64 * 1024)
#define PFR_READBACK_CHUNK (16 * 1024)

/*
 * The PLDM-staged image is the bare FLSH bundle (Caliptra FMC/RT + SoC
 * manifest + MCU runtime) built as "manifest_image" and, per
 * manifest_image_seek_kb in ast1080/ast1080a0/dcscm/BUILD.bazel, it belongs
 * at this offset within active_partition, not at offset 0: the first 1 MiB
 * holds ssmcu_rom (ssmcu_rom_seek_kb=0); bootmcu_rom has been removed along
 * with its caliptra-mcu-sw support, leaving 0x080000-0x100000 unused rather
 * than reclaimed. Writing the bundle at offset 0 overwrites the ssmcu ROM
 * image and bricks the board.
 */
#define PFR_FLSH_MANIFEST_IMAGE_OFFSET (1024 * 1024)

extern uint8_t pldm_fw_update(void *fw_update_param, const int flash_position);

static struct {
	uint8_t *buffer;
	size_t size;
} update_image;

static uint8_t pfr_flsh_pre_update(void *arg)
{
	pldm_fw_update_param_t *param = arg;

	if ((param == NULL) ||
	    (param->fw_update_cfg.max_buff_size < PFR_PLDM_MIN_TRANSFER_SIZE) ||
	    (param->fw_update_cfg.image_size == 0) ||
	    (param->fw_update_cfg.image_size > CONFIG_PFR_PLDM_MAX_IMAGE_SIZE) ||
	    (param->fw_update_cfg.image_size >
	     (FIXED_PARTITION_SIZE(active_partition) - PFR_FLSH_MANIFEST_IMAGE_OFFSET))) {
		LOG_ERR("Invalid PLDM transfer/image size: transfer=%u image=%u",
			param ? param->fw_update_cfg.max_buff_size : 0,
			param ? param->fw_update_cfg.image_size : 0);
		return 1;
	}

	update_image.buffer = k_malloc(param->fw_update_cfg.image_size);
	if (update_image.buffer == NULL) {
		LOG_ERR("Unable to allocate %u-byte FLSH staging buffer",
			param->fw_update_cfg.image_size);
		return 1;
	}
	update_image.size = param->fw_update_cfg.image_size;
	param->user_data = update_image.buffer;
	LOG_INF("FLSH RAM staging allocated: %u bytes", param->fw_update_cfg.image_size);
	return 0;
}

static uint8_t pfr_flsh_update(void *arg)
{
	pldm_fw_update_param_t *param = arg;

	if ((param == NULL) || (param->user_data != update_image.buffer) ||
	    ((uint64_t)param->data_ofs + param->data_len > update_image.size)) {
		LOG_ERR("Rejected out-of-range PLDM firmware data");
		return 1;
	}

	memcpy(update_image.buffer + param->data_ofs, param->data, param->data_len);
	return pldm_fw_update(param, 0);
}

static uint8_t pfr_flsh_post_update(void *arg)
{
	pldm_fw_update_param_t *param = arg;

	if (update_image.buffer != NULL) {
		k_free(update_image.buffer);
		update_image.buffer = NULL;
		update_image.size = 0;
	}
	if (param != NULL)
		param->user_data = NULL;
	return 0;
}

static uint8_t pfr_flsh_verify(void *arg)
{
	ARG_UNUSED(arg);

	if ((update_image.buffer == NULL) || (update_image.size == 0) ||
	    pfr_pldm_flsh_validate(update_image.buffer, update_image.size))
		return PLDM_FW_UPDATE_VERIFY_COMPLETE_WITH_VERIFICATION_FAILURE;

	LOG_INF("FLSH verification complete");
	return PLDM_FW_UPDATE_VERIFY_SUCCESS;
}

static int pfr_hash_buffer(const uint8_t *buffer, size_t size, uint8_t digest[48])
{
	return mbedtls_sha512(buffer, size, digest, 1);
}

static int pfr_hash_flash(const struct device *flash, off_t offset, size_t size,
			  uint8_t digest[48])
{
	mbedtls_sha512_context sha;
	uint8_t *buffer;
	size_t done = 0;
	int ret;

	buffer = k_malloc(PFR_READBACK_CHUNK);
	if (buffer == NULL)
		return -ENOMEM;

	mbedtls_sha512_init(&sha);
	ret = mbedtls_sha512_starts(&sha, 1);
	while ((ret == 0) && (done < size)) {
		size_t length = MIN((size_t)PFR_READBACK_CHUNK, size - done);

		ret = flash_read(flash, offset + done, buffer, length);
		if (ret == 0)
			ret = mbedtls_sha512_update(&sha, buffer, length);
		done += length;
	}
	if (ret == 0)
		ret = mbedtls_sha512_finish(&sha, digest);
	mbedtls_sha512_free(&sha);
	k_free(buffer);
	return ret;
}

static uint8_t pfr_flsh_apply(void *arg)
{
	const struct device *flash = FIXED_PARTITION_DEVICE(active_partition);
	const struct flash_parameters *parameters;
	const off_t active_offset =
		FIXED_PARTITION_OFFSET(active_partition) + PFR_FLSH_MANIFEST_IMAGE_OFFSET;
	struct flash_pages_info page;
	uint8_t staged_digest[48];
	uint8_t flash_digest[48];
	size_t erase_size;
	size_t done = 0;
	int ret;

	ARG_UNUSED(arg);

	if ((update_image.buffer == NULL) || !device_is_ready(flash))
		return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;

	parameters = flash_get_parameters(flash);
	if ((parameters == NULL) || (parameters->write_block_size == 0) ||
	    ((active_offset % parameters->write_block_size) != 0)) {
		LOG_ERR("Active flash offset is not aligned to the flash write block");
		return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;
	}

	ret = pfr_hash_buffer(update_image.buffer, update_image.size, staged_digest);
	if (ret != 0)
		return PLDM_FW_UPDATE_APPLY_GENERIC_ERROR_OCCURRED;

	ret = flash_get_page_info_by_offs(flash, active_offset, &page);
	if ((ret != 0) || (page.size == 0)) {
		LOG_ERR("Unable to determine active flash erase size: %d", ret);
		return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;
	}
	erase_size = ROUND_UP(update_image.size, page.size);
	if (erase_size > (FIXED_PARTITION_SIZE(active_partition) - PFR_FLSH_MANIFEST_IMAGE_OFFSET)) {
		LOG_ERR("Rounded erase size 0x%zx exceeds active partition", erase_size);
		return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;
	}

	LOG_WRN("Replacing active FMC region: offset=0x%lx image=0x%zx erase=0x%zx",
		(long)active_offset, update_image.size, erase_size);
	ret = flash_erase(flash, active_offset, erase_size);
	if (ret != 0) {
		LOG_ERR("Active flash erase failed: %d", ret);
		return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;
	}

	while (done < update_image.size) {
		size_t length = MIN((size_t)PFR_FLASH_IO_CHUNK, update_image.size - done);
		size_t padded_length = ROUND_UP(length, parameters->write_block_size);

		if (padded_length == length) {
			ret = flash_write(flash, active_offset + done, update_image.buffer + done,
					   length);
		} else {
			/*
			 * Final chunk is shorter than a write block. Pad it with
			 * 0xFF (the erased-flash value, already true of this range
			 * after the erase above) so the write length satisfies the
			 * driver's write-block-size requirement.
			 */
			uint8_t *padded = k_malloc(padded_length);

			if (padded == NULL)
				return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;
			memcpy(padded, update_image.buffer + done, length);
			memset(padded + length, 0xFF, padded_length - length);
			ret = flash_write(flash, active_offset + done, padded, padded_length);
			k_free(padded);
		}
		if (ret != 0) {
			LOG_ERR("Active flash write failed at 0x%zx: %d", done, ret);
			return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;
		}
		done += length;
	}

	ret = pfr_hash_flash(flash, active_offset, update_image.size, flash_digest);
	if ((ret != 0) || (memcmp(staged_digest, flash_digest, sizeof(staged_digest)) != 0)) {
		LOG_ERR("Active flash readback SHA-384 mismatch");
		return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;
	}

	LOG_INF("Active FMC replacement and SHA-384 readback verification complete");
	return PLDM_FW_UPDATE_APPLY_SUCCESS;
}

static bool pfr_flsh_get_version(void *info, uint8_t *buffer, uint8_t *length)
{
	static const char version[] = "ast1080-flsh-active";

	ARG_UNUSED(info);
	if ((buffer == NULL) || (length == NULL))
		return false;
	memcpy(buffer, version, sizeof(version) - 1);
	*length = sizeof(version) - 1;
	return true;
}

static pldm_fw_update_info_t pfr_components[] = {
	{
		.enable = true,
		.comp_classification = COMP_CLASS_TYPE_FW,
		.comp_identifier = PFR_FLSH_COMPONENT_ID,
		.comp_classification_index = 0,
		.pre_update_func = pfr_flsh_pre_update,
		.update_func = pfr_flsh_update,
		.pos_update_func = pfr_flsh_post_update,
		.verify_func = pfr_flsh_verify,
		.inf = COMP_UPDATE_VIA_SPI,
		.activate_method = COMP_ACT_MED_RESET,
		.get_fw_version_fn = pfr_flsh_get_version,
		.self_apply_work_func = pfr_flsh_apply,
	},
	{
		.enable = true,
		.comp_classification = COMP_CLASS_TYPE_FW,
		.comp_identifier = PFR_CM4_COMPONENT_ID,
		.comp_classification_index = 0,
		.pre_update_func = pfr_flsh_pre_update,
		.update_func = pfr_flsh_update,
		.pos_update_func = pfr_flsh_post_update,
		.verify_func = pfr_flsh_verify,
		.inf = COMP_UPDATE_VIA_SPI,
		/* The active FLSH is selected after a platform reset.  Do not
		 * advertise self-contained activation to the update agent.
		 */
		.activate_method = COMP_ACT_MED_RESET,
		.get_fw_version_fn = pfr_flsh_get_version,
		.self_apply_work_func = pfr_flsh_apply,
	}
};

void load_pldmupdate_comp_config(void)
{
	if (comp_config == NULL) {
		comp_config = pfr_components;
		comp_config_count = ARRAY_SIZE(pfr_components);
	}
}

uint8_t plat_pldm_query_device_identifiers(const uint8_t *buf, uint16_t len,
					   uint8_t *resp, uint16_t *resp_len)
{
	struct pldm_query_device_identifiers_resp *response =
		(struct pldm_query_device_identifiers_resp *)resp;
	struct pldm_descriptor_tlv *tlv;
	static const uint8_t iana[] = { 0x00, 0x00, 0xa0, 0x15 };

	ARG_UNUSED(buf);
	ARG_UNUSED(len);
	if ((resp == NULL) || (resp_len == NULL))
		return PLDM_ERROR;

	response->completion_code = PLDM_SUCCESS;
	response->descriptor_count = 1;
	response->device_identifiers_len = sizeof(struct pldm_descriptor_tlv) + sizeof(iana) - 1;
	tlv = (struct pldm_descriptor_tlv *)(resp + sizeof(*response));
	tlv->descriptor_type = PLDM_FWUP_IANA_ENTERPRISE_ID;
	tlv->descriptor_length = sizeof(iana);
	memcpy(tlv->descriptor_data, iana, sizeof(iana));
	*resp_len = sizeof(*response) + response->device_identifiers_len;
	return PLDM_SUCCESS;
}
