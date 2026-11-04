# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(aspeed-obmf)

# Headers outside a source's own directory are included as "<dir>/<file>.h",
# so every cross-directory dependency is visible at the include site.
# lstp/ is the core and includes nothing outside itself.
target_include_directories(app PRIVATE src)

target_sources(app PRIVATE src/main.c)

# Root of the "obmf" command tree. Every other shell file adds its node to it,
# so it has to be there whenever the shell is.
target_sources_ifdef(CONFIG_SHELL app PRIVATE src/obmf_shell.c)

# The core and UART are always built. Other channel directories are built when
# their Kconfig option is set.
add_subdirectory(src/lstp)
add_subdirectory(src/uart)
add_subdirectory_ifdef(CONFIG_OBMF_LSTP_SPI_CHANNEL src/spi)
add_subdirectory_ifdef(CONFIG_OBMF_LSTP_MTD_CLIENT src/mtd)
