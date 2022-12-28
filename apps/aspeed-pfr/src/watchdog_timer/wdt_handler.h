/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>

void bmc_wdt_handler(uint8_t cmd);
void me_wdt_timer_handler(uint8_t cmd);
void acm_wdt_handler(uint8_t cmd);
void bios_wdt_handler(uint8_t cmd);

