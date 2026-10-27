# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_ASPEED_SDHCI)
  zephyr_library()
  zephyr_library_sources(aspeed_sdhci.c)
endif()
