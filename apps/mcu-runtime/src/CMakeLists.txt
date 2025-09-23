# SPDX-License-Identifier: Apache-2.0

# Generate aspeed-zephyr-project version header
execute_process(
  COMMAND bash -c "git tag --sort=-v:refname | head -n 1"
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE ASPEED_ZEPHYR_PROJECT_TAG
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)
execute_process(
  COMMAND git rev-parse --short HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE ASPEED_ZEPHYR_PROJECT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)
execute_process(
  COMMAND bash -c "git diff --quiet || echo dirty-"
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE ASPEED_ZEPHYR_PROJECT_DIRTY
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)
execute_process(
  COMMAND bash -c "date '+%Y-%m-%d %H:%M:%S'"
  OUTPUT_VARIABLE ASPEED_ZEPHYR_PROJECT_BUILD_TIMESTAMP
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(ASPEED_ZEPHYR_PROJECT_VERSION "${ASPEED_ZEPHYR_PROJECT_TAG}-${ASPEED_ZEPHYR_PROJECT_DIRTY}${ASPEED_ZEPHYR_PROJECT_HASH}")
set(ASPEED_ZEPHYR_PROJECT_VERSION_HEADER "${CMAKE_BINARY_DIR}/aspeed_zephyr_project_version.h")
set(ASPEED_ZEPHYR_PROJECT_VERSION_HEADER_CONTENT "#ifndef ASPEED_ZEPHYR_PROJECT_VERSION_H\n#define ASPEED_ZEPHYR_PROJECT_VERSION_H\n\n#define ASPEED_ZEPHYR_PROJECT_VERSION \"${ASPEED_ZEPHYR_PROJECT_VERSION}\"\n#define ASPEED_ZEPHYR_PROJECT_BUILD_TIMESTAMP \"${ASPEED_ZEPHYR_PROJECT_BUILD_TIMESTAMP}\"\n\n#endif // ASPEED_ZEPHYR_PROJECT_VERSION_H\n")
file(WRITE ${ASPEED_ZEPHYR_PROJECT_VERSION_HEADER} "${ASPEED_ZEPHYR_PROJECT_VERSION_HEADER_CONTENT}")
if(TARGET app)
  target_include_directories(app PRIVATE ${CMAKE_BINARY_DIR})
endif()

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
	usb_recovery.c
	uart.c
	chip.c
	board.c
	ssp_tsp.c
	manifest.c
	manifest_image.c
	manifest_image_sig.c
	ast_loader.c
	wdt.c
	extrst.c
	cptra_idevid.c
	usb.c
)

#target_sources_ifdef(CONFIG_SLI_AST2700 app PRIVATE sli_ast2700.c)
add_subdirectory(sli)
