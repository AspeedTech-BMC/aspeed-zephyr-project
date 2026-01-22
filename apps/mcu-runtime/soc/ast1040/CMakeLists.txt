# Copyright (c) 2025 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

target_sources(app PRIVATE
	chip_ast1040.c
	board_ast1040.c
	ssp_tsp_ast1040.c
	extrst_ast1040.c
	usb_recovery_ast1040.c
	stor_ast1040.c
)

target_include_directories(app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)