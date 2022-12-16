/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_INTEL_PFR)
#include <stdint.h>

int intel_pfr_update_verify(struct firmware_image *fw, struct hash_engine *hash, struct rsa_engine *rsa);
int update_firmware_image(uint32_t image_type, void *AoData, void *EventContext);

#if defined(CONFIG_SEAMLESS_UPDATE)
int perform_seamless_update(uint32_t image_type, void *AoData, void *EventContext);
#endif

int firmware_image_verify(struct firmware_image *fw, struct hash_engine *hash, struct rsa_engine *rsa);
#endif // CONFIG_INTEL_PFR
