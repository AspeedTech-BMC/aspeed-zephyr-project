# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_CLOCK_CONTROL_AST27XX_SCU0)
  zephyr_library()
  zephyr_library_sources(clock_control_ast27xx_scu0.c)
endif()
