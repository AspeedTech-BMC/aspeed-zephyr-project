# Copyright (c) 2025 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(aspeed_irot)

zephyr_include_directories(lib/dtc/libfdt)
zephyr_include_directories(.)

add_subdirectory(src)
add_subdirectory(lib)

