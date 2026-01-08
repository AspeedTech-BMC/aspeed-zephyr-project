# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(aspeed_irot)

zephyr_include_directories(.)
zephyr_include_directories(src)

add_subdirectory(src)

