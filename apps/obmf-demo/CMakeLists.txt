# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(obmf-demo)

target_sources(app PRIVATE
    src/main.c
    src/lstp_usb.c
    src/lstp_router.c
    src/lstp_task.c
    src/lstp_i2c.c
    src/lstp_spi.c
    src/lstp_uart.c
)
