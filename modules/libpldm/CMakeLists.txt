# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

if(CONFIG_PLDM)
	# <uchar.h> shim for C libraries without one, and <libpldm/sizes.h>,
	# which libpldm generates only in its meson build
	zephyr_include_directories(include)
endif()

if(CONFIG_PLDM_RESPONDER)
	set(PLDM_ROOT ${ZEPHYR_LIBPLDM_MODULE_DIR})

	zephyr_library_named(pldm_responder)
	zephyr_library_sources(
		${PLDM_ROOT}/src/control.c
		${PLDM_ROOT}/src/firmware_device/fd.c
	)
	# The LIBPLDM_ABI_* and _GNU_SOURCE definitions are PUBLIC on the
	# module's library
	zephyr_library_link_libraries(modules_pldm)
endif()
