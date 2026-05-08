# Copyright (c) 2025 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

target_sources(app PRIVATE
	chip_ast2700.c
	board_ast2700.c
	ssp_tsp_ast2700.c
	extrst_ast2700.c
	fpga_phy.c
	dp.c
	vga.c
	pci.c
	sdram_ast2700.c
	sdram_phy.c
	ufs.c
	usb_recovery_ast2700.c
	usb.c
	mmc.c
	stor_ast2700.c
	mac.c
)

target_include_directories(app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_subdirectory(sli)
