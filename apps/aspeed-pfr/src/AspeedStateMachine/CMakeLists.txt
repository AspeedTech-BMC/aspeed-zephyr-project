# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

target_sources(app PRIVATE AspeedStateMachine.c)

if(CONFIG_SHELL)
	target_sources(app PRIVATE TestShell.c)
endif()
