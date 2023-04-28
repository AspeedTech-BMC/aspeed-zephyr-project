/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include "platform_monitor/platform_monitor.h"

void bmc_wdt_handler(uint8_t cmd);
#if defined(CONFIG_INTEL_PFR)
#ifdef SUPPORT_ME
void me_wdt_timer_handler(uint8_t cmd);
#endif
void acm_wdt_handler(uint8_t cmd);
#endif
void bios_wdt_handler(uint8_t cmd);
