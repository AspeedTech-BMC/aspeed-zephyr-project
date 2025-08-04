# SPDX-License-Identifier: Apache-2.0

zephyr_include_directories(include)

target_sources(app PRIVATE
	main.c
	sdram_ast2700.c
	sdram_phy.c
	fpga_phy.c
	abr.c
	dp.c
	pci.c
	vga.c
	spi.c
	mmc.c
	ufs.c
	stor.c
	recovery.c
	i2c.c
	i3c.c
	usb.c
	uart.c
	chip.c
	board.c
	ssp_tsp.c
	manifest.c
	manifest_image.c
	manifest_image_sig.c
	ast_loader.c
)

#target_sources_ifdef(CONFIG_SLI_AST2700 app PRIVATE sli_ast2700.c)
add_subdirectory(sli)
