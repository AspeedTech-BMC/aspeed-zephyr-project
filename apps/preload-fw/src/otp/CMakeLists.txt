# Copyright (c) 2023 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT
target_sources(app PRIVATE otp_sim.c)
target_sources(app PRIVATE otp_flash_shell.c)
target_sources_ifdef(CONFIG_BOARD_AST1060_DCSCM_DICE app PRIVATE otp_utils.c)
