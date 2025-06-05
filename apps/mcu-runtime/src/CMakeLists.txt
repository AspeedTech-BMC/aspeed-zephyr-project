# SPDX-License-Identifier: Apache-2.0

zephyr_include_directories(include)

target_sources(app PRIVATE
	main.c
	sdram_ast2700.c
	sdram_phy.c
	fpga_phy.c
	fmc_hdr.c
	abr.c
	dp.c
	pci.c
	vga.c
	spi.c
	mmc.c
	ufs.c
	stor.c
	ssp_tsp.c
	fit.c
	fit_image.c
	fit_image_sig.c
)

#target_sources_ifdef(CONFIG_SLI_AST2700 app PRIVATE sli_ast2700.c)
add_subdirectory(sli)
