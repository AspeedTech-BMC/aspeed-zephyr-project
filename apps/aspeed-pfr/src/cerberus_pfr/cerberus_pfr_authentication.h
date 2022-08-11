/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_CERBERUS_PFR)
#include "pfr/pfr_common.h"

int pfr_active_verify(struct pfr_manifest *manifest);
int pfr_recovery_verify(struct pfr_manifest *manifest);
#endif // CONFIG_CERBERUS_PFR

