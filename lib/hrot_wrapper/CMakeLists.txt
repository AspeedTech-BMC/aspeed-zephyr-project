# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

if (CONFIG_HROT_WRAPPER)
	zephyr_interface_library_named(hrot_wrapper)

	target_include_directories(hrot_wrapper INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

	zephyr_library()

	set(WRAPPER_DIR ${CMAKE_CURRENT_LIST_DIR})

	# Collect the Source Build Files
	file(GLOB_RECURSE WRAPPER_SOURCES "${WRAPPER_DIR}/*.c")
	set(WRAPPER_INCLUDES ${WRAPPER_DIR})
	set(CERBERUS_ROOT $ENV{ZEPHYR_BASE}/../middlewares/cerberus)

	zephyr_library_sources(
		${WRAPPER_SOURCES}
	)

	zephyr_library_include_directories(
		${CERBERUS_ROOT}/core/
		${CERBERUS_ROOT}/projects/
		${CERBERUS_ROOT}/projects/zephyr
		${WRAPPER_INCLUDES}/
		../hrot_hal
	)

	zephyr_library_link_libraries(hrot_wrapper)
endif()
