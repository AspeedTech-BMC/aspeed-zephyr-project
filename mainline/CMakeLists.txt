# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

# module.yml's dts_root adds include/ to the devicetree preprocessor search
# path before this file runs. Export the same headers to C sources.
zephyr_include_directories(include)

add_subdirectory(drivers)

# The libraries and modules the repository root module provides on the vendor
# Zephyr tree. The root module is not loaded with upstream Zephyr, because its
# board root holds boards for SoCs upstream Zephyr does not define.
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../lib ${CMAKE_CURRENT_BINARY_DIR}/lib)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../modules ${CMAKE_CURRENT_BINARY_DIR}/modules)
