/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include "manifest/pfm/pfm_manager.h"

int intel_pfr_recovery_verify(struct recovery_image *image, struct hash_engine *hash,
			      struct signature_verification *verification, uint8_t *hash_out, size_t hash_length,
			      struct pfm_manager *pfm);

