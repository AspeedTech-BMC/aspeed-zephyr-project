/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef INTEL_PFR_PBC_H_
#define INTEL_PFR_PBC_H_
#include "intel_pfr_definitions.h"

int decompress_capsule(struct pfr_manifest *manifest, DECOMPRESSION_TYPE_MASK_ENUM decomp_type);
#endif /*INTEL_PFR_PBC_H_*/
