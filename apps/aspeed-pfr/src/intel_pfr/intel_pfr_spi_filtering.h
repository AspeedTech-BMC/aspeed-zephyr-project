/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_INTEL_PFR)
void apply_pfm_protection(int spi_device_id);
#endif
