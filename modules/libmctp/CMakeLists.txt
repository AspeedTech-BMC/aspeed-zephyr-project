# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

# Zephyr glue for libmctp. libmctp itself is built by its own module
# (modules/lib/libmctp/zephyr/CMakeLists.txt).
if(CONFIG_MCTP)
	zephyr_include_directories(include)

	zephyr_library()
	zephyr_library_sources(mctp_memory.c)
	zephyr_library_sources_ifdef(CONFIG_MCTP_LOG_CUSTOM_ZEPHYR mctp_log.c)
	zephyr_library_sources_ifdef(CONFIG_MCTP_I3C_TARGET_MQUEUE mctp_i3c_tmq.c)
	zephyr_library_sources_ifdef(CONFIG_MCTP_USB mctp_usb.c)
	zephyr_linker_sources_ifdef(CONFIG_MCTP_USB SECTIONS mctp_usb.ld)
endif()
