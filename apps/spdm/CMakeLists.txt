# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

find_package(Zephyr HINTS $ENV{ZEPHYR_BASE})
project(ast1030_spdm)

#zephyr_link_libraries(mbedTLS)
#zephyr_include_directories(mbedTLS)

add_subdirectory(src)
