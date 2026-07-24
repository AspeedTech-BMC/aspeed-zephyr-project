# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT
target_sources(app PRIVATE
	cmd_channel_mctp.c
	mctp.c
	mctp_smbus.c
	mctp_task.c
	plat_mctp.c
	)

if(CONFIG_PFR_MCTP_I3C)
	target_sources(app PRIVATE mctp_i3c_common.c)
	if(CONFIG_PFR_MCTP_I3C_5_0)
		target_sources(app PRIVATE mctp_i3c_target.c mctp_i3c_target_state.c)
	else()
		target_sources(app PRIVATE mctp_i3c.c)
		if(CONFIG_I3C_MIPI_HCI)
			target_sources(app PRIVATE mctp_i3c_mipi.c)
		else()
			target_sources(app PRIVATE mctp_i3c_ast1060.c)
		endif()
	endif()
endif()

if(CONFIG_SHELL)
	target_sources(app PRIVATE test_mctp_shell.c)
endif()
