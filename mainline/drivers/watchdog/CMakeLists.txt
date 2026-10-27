# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_WDT_ASPEED)
  zephyr_library()
  zephyr_library_sources(wdt_aspeed.c)
endif()
