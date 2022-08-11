/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_INTEL_PFR)
#include <stdint.h>
#include "manifest/pfm/pfm_manager.h"

int intel_pfr_recovery_verify(struct recovery_image *image, struct hash_engine *hash,
			      struct signature_verification *verification, uint8_t *hash_out,
			      size_t hash_length, struct pfm_manager *pfm);
int pfr_recover_recovery_region(int image_type, uint32_t source_address, uint32_t target_address);
int pfr_staging_pch_staging(struct pfr_manifest *manifest);
int intel_pfr_recover_update_action(struct pfr_manifest *manifest);
int pfr_active_recovery_svn_validation(struct pfr_manifest *manifest);
int pfr_recover_active_region(struct pfr_manifest *manifest);
int recovery_verify(struct recovery_image *image, struct hash_engine *hash,
		    struct signature_verification *verification, uint8_t *hash_out,
		    size_t hash_length, struct pfm_manager *pfm);
int recovery_apply_to_flash(struct recovery_image *image, struct spi_flash *flash);
#endif
