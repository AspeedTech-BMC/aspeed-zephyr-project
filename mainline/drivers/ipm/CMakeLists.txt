# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_IPM_BOOTMCU)
  zephyr_library()
  zephyr_library_sources(ipm_bootmcu.c)
endif()
