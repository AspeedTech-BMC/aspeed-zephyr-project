# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_RESET_AST27XX)
  zephyr_library()
  zephyr_library_sources(reset_ast27xx.c)
endif()
