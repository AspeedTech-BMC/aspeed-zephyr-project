# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_SPI_NOR_MULTI_DEV)
  zephyr_library()
  zephyr_library_sources(spi_nor_multi_dev.c jesd216.c)
endif()
