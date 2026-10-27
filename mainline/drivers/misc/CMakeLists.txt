# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_OTP_AST27XX)
  zephyr_library()
  zephyr_library_sources(otp_ast2700.c lib_otp_ast2700.c)
endif()
