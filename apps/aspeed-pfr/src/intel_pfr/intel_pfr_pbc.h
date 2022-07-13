/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "intel_pfr_definitions.h"

int decompress_capsule(struct pfr_manifest *manifest, DECOMPRESSION_TYPE_MASK_ENUM decomp_type);

#if defined(CONFIG_SEAMLESS_UPDATE)
int decompress_fv_capsule(struct pfr_manifest *manifest);
#endif
