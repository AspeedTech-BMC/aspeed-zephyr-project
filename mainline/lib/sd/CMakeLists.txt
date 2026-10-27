# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_MMC_STACK AND CONFIG_SOC_AST2700_BOOTMCU)
  zephyr_library()
  zephyr_library_include_directories(${ZEPHYR_BASE}/subsys/sd)
  zephyr_library_sources(mmc.c)
endif()
