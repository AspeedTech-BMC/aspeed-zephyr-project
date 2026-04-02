/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PLDM_FW_UPDATE_MBEDTLS_SHA384_H
#define PLDM_FW_UPDATE_MBEDTLS_SHA384_H

#include "pldm_firmware_update.h"
#include "pldm_fw_update_component_ids.h"

uint8_t pldm_mbedtls_sha384_pre_update(void *fw_update_param);
uint8_t pldm_mbedtls_sha384_update(void *fw_update_param);
uint8_t pldm_mbedtls_sha384_post_update(void *fw_update_param);
uint8_t pldm_mbedtls_sha384_activate(void *arg);
bool pldm_mbedtls_sha384_get_fw_version(void *info_p, uint8_t *buf, uint8_t *len);

#endif /* PLDM_FW_UPDATE_MBEDTLS_SHA384_H */
