# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

target_sources(app
	PRIVATE
	main.c
	psp/loader.c
	psp/loader_shell.c
	state_machine/irot_fsm.c
	state_machine/irot_shell.c
)
