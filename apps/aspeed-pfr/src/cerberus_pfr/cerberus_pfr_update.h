/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_CERBERUS_PFR)

#include <stdint.h>
#include "firmware/firmware_image.h"
#include "pfr/pfr_common.h"

int cerberus_pfr_update_verify(struct firmware_image *fw, struct hash_engine *hash, struct rsa_engine *rsa);

int firmware_image_verify(struct firmware_image *fw, struct hash_engine *hash, struct rsa_engine *rsa);
int update_firmware_image(uint32_t image_type, void *AoData, void *EventContext);
int get_ufm_svn(struct pfr_manifest *manifest, uint8_t offset);
#endif // CONFIG_CERBERUS_PFR
