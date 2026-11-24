# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_OTP_AST27XX OR CONFIG_PRIVILEGE_CTRL OR CONFIG_EDAF_BRIDGE_ASPEED OR
   CONFIG_CPTRA_UPDATE OR CONFIG_CPTRA_IFC OR CONFIG_CPTRA_MBOX OR
   CONFIG_CPTRA_DICE OR CONFIG_CPTRA_MISC OR CONFIG_CPTRA_IPC OR CONFIG_OTP_IPC)
  zephyr_library()
  zephyr_library_sources_ifdef(CONFIG_OTP_AST27XX otp_ast2700.c lib_otp_ast2700.c)
  zephyr_library_sources_ifdef(CONFIG_PRIVILEGE_CTRL prictrl_aspeed.c)
  zephyr_library_sources_ifdef(CONFIG_EDAF_BRIDGE_ASPEED edaf_bridge_aspeed.c)
  zephyr_library_sources_ifdef(CONFIG_CPTRA_UPDATE cptra_update.c)
  zephyr_library_sources_ifdef(CONFIG_CPTRA_IFC cptra_ifc.c)
  zephyr_library_sources_ifdef(CONFIG_CPTRA_MBOX cptra_mbox.c)
  zephyr_library_sources_ifdef(CONFIG_CPTRA_DICE cptra_dice.c)
  zephyr_library_sources_ifdef(CONFIG_CPTRA_MISC cptra_misc.c)
  zephyr_library_sources_ifdef(CONFIG_CPTRA_IPC cptra_ipc.c)
  zephyr_library_sources_ifdef(CONFIG_OTP_IPC otp_ipc.c)
endif()
