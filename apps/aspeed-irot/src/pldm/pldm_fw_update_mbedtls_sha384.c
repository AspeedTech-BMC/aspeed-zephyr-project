/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <stdlib.h>
#include <zephyr/logging/log.h>
#include <zephyr/multi_heap/shared_multi_heap.h>
#include <zephyr/sys/util.h>

#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/version.h>

#include "pldm_fw_update_mbedtls_sha384.h"

LOG_MODULE_REGISTER(pldm_fw_update_mbedtls_sha384, LOG_LEVEL_DBG);

extern uint8_t pldm_fw_update(void *fw_update_param, const int flash_position);

static mbedtls_sha512_context sha512_ctx;

uint8_t pldm_mbedtls_sha384_pre_update(void *fw_update_param)
{
	pldm_fw_update_param_t *p = (pldm_fw_update_param_t *)fw_update_param;

	if (p == NULL) {
		return 1;
	}

	LOG_INF("MBEDTLS SHA384 PRE UPDATE");

	mbedtls_sha512_init(&sha512_ctx);
	mbedtls_sha512_starts(&sha512_ctx, 1);

	p->user_data = shared_multi_heap_alloc(SMH_REG_ATTR_NON_CACHEABLE,
					       p->fw_update_cfg.image_size);
	LOG_INF("Allocated non-cache memory for one-shot hash calculation at address 0x%08X, size %u",
		(uint32_t)p->user_data, p->fw_update_cfg.image_size);

	return 0;
}

uint8_t pldm_mbedtls_sha384_post_update(void *fw_update_param)
{
	pldm_fw_update_param_t *p = (pldm_fw_update_param_t *)fw_update_param;
	uint8_t hash_onfly[64] = { 0 };

	if (p == NULL) {
		return 1;
	}

	mbedtls_sha512_finish(&sha512_ctx, hash_onfly);
	mbedtls_sha512_free(&sha512_ctx);

	LOG_HEXDUMP_INF(hash_onfly, 48, "POST UPDATE HASH SHA384 ON THE FLY");

	shared_multi_heap_free(p->user_data);
	p->user_data = NULL;
	return 0;
}

uint8_t pldm_mbedtls_sha384_update(void *fw_update_param)
{
	pldm_fw_update_param_t *p = (pldm_fw_update_param_t *)fw_update_param;

	if (p == NULL) {
		return 1;
	}

	mbedtls_sha512_update(&sha512_ctx, p->data, p->data_len);
	memcpy((uint8_t *)p->user_data + p->data_ofs, p->data, p->data_len);

	pldm_fw_update(fw_update_param, 0);
	return 0;
}

uint8_t pldm_mbedtls_sha384_activate(void *arg)
{
	ARG_UNUSED(arg);

	LOG_INF("MBEDTLS SHA384 ACTIVATE DUMMY");
	return 0;
}

bool pldm_mbedtls_sha384_get_fw_version(void *info_p, uint8_t *buf, uint8_t *len)
{
	uint8_t version_str_len = strlen(MBEDTLS_VERSION_STRING_FULL);

	ARG_UNUSED(info_p);

	if (buf == NULL || len == NULL) {
		return false;
	}

	memcpy(buf, MBEDTLS_VERSION_STRING_FULL, version_str_len);
	*len = version_str_len;

	return true;
}
