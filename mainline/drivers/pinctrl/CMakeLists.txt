# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_PINCTRL_ASPEED_G7)
  # pinctrl.h and its users need the same SoC types and DT initializer macros.
  zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})
  zephyr_library()
  zephyr_library_sources(pinctrl_aspeed_g7_soc1.c)
endif()
