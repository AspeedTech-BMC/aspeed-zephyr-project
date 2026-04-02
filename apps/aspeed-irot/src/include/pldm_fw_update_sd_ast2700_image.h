/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PLDM_FW_UPDATE_SD_AST2700_IMAGE_H
#define PLDM_FW_UPDATE_SD_AST2700_IMAGE_H

#include "pldm_firmware_update.h"
#include "pldm_fw_update_component_ids.h"

uint8_t pldm_sd_ast2700_image_pre_update(void *fw_update_param);
uint8_t pldm_sd_ast2700_image_update(void *fw_update_param);
uint8_t pldm_sd_ast2700_image_post_update(void *fw_update_param);
uint8_t pldm_sd_ast2700_image_verify(void *fw_update_param);
uint8_t pldm_sd_ast2700_image_apply(void *arg);
uint8_t pldm_sd_ast2700_image_activate(void *arg);
bool pldm_sd_ast2700_image_get_fw_version(void *info_p, uint8_t *buf, uint8_t *len);

#endif /* PLDM_FW_UPDATE_SD_AST2700_IMAGE_H */
