# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

zephyr_include_directories(include)

target_sources(app
	PRIVATE
	main.c
	psp/loader.c
	psp/loader_shell.c
	state_machine/irot_fsm.c
	state_machine/irot_shell.c
	image/caliptra_soc_manifest.c

	cptra/cptra_sample.c
	cptra/cptra_idevid.c

	cptra/cptra_mbedtls.c
	cptra/cptra_api.c
)
