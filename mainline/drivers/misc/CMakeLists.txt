# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_OTP_AST27XX OR CONFIG_PRIVILEGE_CTRL OR CONFIG_EDAF_BRIDGE_ASPEED)
  zephyr_library()
  zephyr_library_sources_ifdef(CONFIG_OTP_AST27XX otp_ast2700.c lib_otp_ast2700.c)
  zephyr_library_sources_ifdef(CONFIG_PRIVILEGE_CTRL prictrl_aspeed.c)
  zephyr_library_sources_ifdef(CONFIG_EDAF_BRIDGE_ASPEED edaf_bridge_aspeed.c)
endif()
