/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_CERBERUS_PFR)

#include <stdint.h>
#include "pfr/pfr_common.h"

uint8_t get_ufm_svn(uint32_t offset);
int pfr_active_recovery_svn_validation(struct pfr_manifest *manifest);

#endif
