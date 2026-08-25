# Copyright (c) 2025 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

add_subdirectory_ifdef(CONFIG_SOC_AST1040_BOOTMCU ast1040)
add_subdirectory_ifdef(CONFIG_SOC_AST2700_BOOTMCU ast2700)
add_subdirectory_ifdef(CONFIG_SOC_AST2705_BOOTMCU ast2700)