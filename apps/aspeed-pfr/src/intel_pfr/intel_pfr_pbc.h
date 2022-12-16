/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "intel_pfr_definitions.h"

#if defined(CONFIG_BMC_CHECKPOINT_RECOVERY) || defined(CONFIG_PCH_CHECKPOINT_RECOVERY)
int get_recovery_level(uint32_t image_type);
void inc_recovery_level(uint32_t image_type);
void reset_recovery_level(uint32_t image_type);
#endif

int update_active_pfm(struct pfr_manifest *manifest);
int decompress_capsule(struct pfr_manifest *manifest, DECOMPRESSION_TYPE_MASK_ENUM decomp_type);

#if defined(CONFIG_SEAMLESS_UPDATE)
int decompress_fv_capsule(struct pfr_manifest *manifest);
#endif

