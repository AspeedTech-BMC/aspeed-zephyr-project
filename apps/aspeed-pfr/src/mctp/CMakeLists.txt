# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT
target_sources(app PRIVATE
	cmd_channel_mctp.c
	mctp.c
	mctp_smbus.c
	mctp_task.c
	plat_mctp.c
	)

if(CONFIG_SHELL)
	target_sources(app PRIVATE test_mctp_shell.c)
endif()
