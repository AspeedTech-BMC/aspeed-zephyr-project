# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.13.1)

find_package(Zephyr HINTS $ENV{ZEPHYR_BASE})
project(aspeed-pfr)

set(ASPEED_PFR_ROOT ${CMAKE_CURRENT_LIST_DIR})

FILE(GLOB_RECURSE app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})

# target_sources(app PRIVATE src/test.c)

set(CERBERUS_ROOT $ENV{ZEPHYR_BASE}/../middlewares/cerberus)

#message(STATUS "Printing app_sources - ${app_sources}")
zephyr_link_libraries(hrot_hal)
zephyr_link_libraries(hrot_wrapper)
zephyr_link_libraries(smf)
zephyr_link_libraries(cerberus)
target_include_directories(
	app
	PRIVATE
	${CERBERUS_ROOT}/core
	${CERBERUS_ROOT}/projects/zephyr
	${ASPEED_PFR_ROOT}/src
	${ASPEED_PFR_ROOT}/src/state_machine
	${ZEPHYR_BASE}/include
	${PROJECT_BINARY_DIR}/include/generated
)

