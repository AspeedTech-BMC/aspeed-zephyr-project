# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_SOC_AST2700_BOOTMCU)
  zephyr_include_directories(.)
  zephyr_sources(soc.c scu1_clk_lock.c sac.c)
  zephyr_sources_ifdef(CONFIG_SCU_POLICY_CTRL sac_scu.c)
endif()
