/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <string.h>
#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/drivers/spi_nor.h>
#include <zephyr/multi_heap/shared_multi_heap.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include "image/caliptra_soc_manifest_v1.h"
#include "cptra/cptra_vendor_key.h"
#include "pldm_fw_update_sd_ast2700_image.h"

LOG_MODULE_REGISTER(pldm_fw_update_sd_ast2700_image, LOG_LEVEL_DBG);

#define AST2700_IMAGE_FLASH_CHUNK_SIZE (1024 * 1024)

extern uint8_t pldm_fw_update(void *fw_update_param, const int flash_position);

static struct {
	void *buffer;
	size_t size;
} ast2700_image_state;

uint8_t pldm_sd_ast2700_image_pre_update(void *fw_update_param)
{
	pldm_fw_update_param_t *p = (pldm_fw_update_param_t *)fw_update_param;

	if (p == NULL) {
		return 1;
	}

	p->user_data = shared_multi_heap_aligned_alloc(SMH_REG_ATTR_NON_CACHEABLE, 16,
						       p->fw_update_cfg.image_size);
	if (p->user_data == NULL) {
		LOG_ERR("AST2700 image buffer allocation failed, size=%u",
			p->fw_update_cfg.image_size);
		return 1;
	}

	ast2700_image_state.buffer = p->user_data;
	ast2700_image_state.size = p->fw_update_cfg.image_size;

	LOG_INF("AST2700 image pre-update, size=%u", p->fw_update_cfg.image_size);
	return 0;
}

uint8_t pldm_sd_ast2700_image_update(void *fw_update_param)
{
	pldm_fw_update_param_t *p = (pldm_fw_update_param_t *)fw_update_param;

	if (p == NULL || p->user_data == NULL) {
		return 1;
	}

	memcpy((uint8_t *)p->user_data + p->data_ofs, p->data, p->data_len);

	return pldm_fw_update(fw_update_param, 0);
}

uint8_t pldm_sd_ast2700_image_post_update(void *fw_update_param)
{
	pldm_fw_update_param_t *p = (pldm_fw_update_param_t *)fw_update_param;

	if (p == NULL) {
		return 1;
	}

	if (p->user_data == NULL) {
		LOG_ERR("AST2700 image post-update buffer is NULL");
		return 1;
	}

	if (p->user_data != NULL) {
		shared_multi_heap_free(p->user_data);
		p->user_data = NULL;
	}
	ast2700_image_state.buffer = NULL;
	ast2700_image_state.size = 0;

	LOG_INF("AST2700 image post-update complete");
	return 0;
}

uint8_t pldm_sd_ast2700_image_verify(void *fw_update_param)
{
	int ret;

	ARG_UNUSED(fw_update_param);

	if (ast2700_image_state.buffer == NULL || ast2700_image_state.size == 0) {
		LOG_ERR("AST2700 image verify buffer is not ready");
		return PLDM_FW_UPDATE_GENERIC_ERROR;
	}

	ret = cptra_validate_vendor_key_hash(
		(const uint8_t *)ast2700_image_state.buffer,
		ast2700_image_state.size);
	if (ret) {
		LOG_ERR("AST2700 vendor key validation failed, ret=%d", ret);
		return PLDM_FW_UPDATE_GENERIC_ERROR;
	}

	ret = cptra_validate_bundle_v1((const uint8_t *)ast2700_image_state.buffer,
				       ast2700_image_state.size);
	if (ret) {
		LOG_ERR("AST2700 image validation failed, ret=%d", ret);
		return PLDM_FW_UPDATE_GENERIC_ERROR;
	}

	LOG_INF("AST2700 image validation passed");
	return PLDM_FW_UPDATE_VERIFY_SUCCESS;
}

uint8_t pldm_sd_ast2700_image_apply(void *arg)
{
	const struct device *flash_dev;
	off_t erase_offset;
	size_t block_erase_size;
	size_t chunk_size;
	size_t erase_size;
	size_t remaining_size;
	size_t sector_erase_size;
	off_t offset;
	uint8_t erase_cmd;
	int ret;

	ARG_UNUSED(arg);

	if (ast2700_image_state.buffer == NULL || ast2700_image_state.size == 0) {
		LOG_ERR("AST2700 image apply buffer is not ready");
		return PLDM_FW_UPDATE_APPLY_GENERIC_ERROR_OCCURRED;
	}

	flash_dev = device_get_binding("fmc@0");
	if (flash_dev == NULL) {
		LOG_ERR("Failed to bind flash device fmc@0");
		return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;
	}

	block_erase_size = spi_nor_get_erase_sz(flash_dev, SPI_NOR_CMD_BE);
	sector_erase_size = spi_nor_get_erase_sz(flash_dev, SPI_NOR_CMD_SE);
	if ((int)sector_erase_size <= 0) {
		LOG_ERR("Failed to get sector erase size");
		return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;
	}

	for (offset = 0, remaining_size = ast2700_image_state.size;
	     remaining_size > 0;
	     offset += chunk_size, remaining_size -= chunk_size) {
		chunk_size = MIN(remaining_size, (size_t)AST2700_IMAGE_FLASH_CHUNK_SIZE);

		state_update(STATE_APPLY);

		for (erase_offset = offset,
		     erase_size = ROUND_UP(chunk_size, sector_erase_size);
		     erase_size > 0;) {
			if ((int)block_erase_size > 0 &&
			    erase_offset % block_erase_size == 0 &&
			    erase_size >= block_erase_size) {
				erase_cmd = SPI_NOR_CMD_BE;
				ret = spi_nor_erase_by_cmd(flash_dev, erase_offset,
							 block_erase_size, erase_cmd);
				if (ret) {
					LOG_ERR("block erase failed at 0x%lx, size=0x%zx, ret=%d",
						(long)erase_offset, block_erase_size, ret);
					return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;
				}
				erase_offset += block_erase_size;
				erase_size -= block_erase_size;
			} else {
				erase_cmd = SPI_NOR_CMD_SE;
				ret = spi_nor_erase_by_cmd(flash_dev, erase_offset,
							 sector_erase_size, erase_cmd);
				if (ret) {
					LOG_ERR("sector erase failed at 0x%lx, size=0x%zx, ret=%d",
						(long)erase_offset, sector_erase_size, ret);
					return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;
				}
				erase_offset += sector_erase_size;
				erase_size -= sector_erase_size;
			}
		}

		ret = flash_write(flash_dev, offset,
				  (const uint8_t *)ast2700_image_state.buffer + offset,
				  chunk_size);
		if (ret) {
			LOG_ERR("flash_write failed at 0x%lx, size=0x%zx, ret=%d",
				(long)offset, chunk_size, ret);
			return PLDM_FW_UPDATE_APPLY_FAIL_WITH_MEMORY_WRITE_ISSUE;
		}

		LOG_INF("programmed fmc@0 offset=0x%lx size=0x%zx",
			(long)offset, chunk_size);
		k_msleep(50);
	}

	return PLDM_FW_UPDATE_APPLY_SUCCESS;
}

uint8_t pldm_sd_ast2700_image_activate(void *arg)
{
	ARG_UNUSED(arg);

	LOG_INF("AST2700 image activate");
	return 0;
}

bool pldm_sd_ast2700_image_get_fw_version(void *info_p, uint8_t *buf, uint8_t *len)
{
	static const char version[] = "ast2700-image";

	ARG_UNUSED(info_p);

	if (buf == NULL || len == NULL) {
		return false;
	}

	memcpy(buf, version, sizeof(version) - 1);
	*len = sizeof(version) - 1;
	return true;
}
