# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

if (CONFIG_HROT_HAL)

	set(HROT_PORT_ROOT ${CMAKE_CURRENT_LIST_DIR} CACHE INTERNAL "HROT_PORT_ROOT")
	
	zephyr_interface_library_named(hrot_middleware)
	zephyr_library()
	
	set(HROT_MIDDLEWARE_ROOT ${CMAKE_CURRENT_LIST_DIR} CACHE INTERNAL "HROT_MIDDLEWARE_ROOT")
	zephyr_library_sources(
	    ${HROT_MIDDLEWARE_ROOT}/flash/flash_aspeed.c
	    ${HROT_MIDDLEWARE_ROOT}/gpio/gpio_aspeed.c
	    ${HROT_MIDDLEWARE_ROOT}/crypto/hash_aspeed.c
	    ${HROT_MIDDLEWARE_ROOT}/crypto/rsa_aspeed.c
	    ${HROT_MIDDLEWARE_ROOT}/crypto/ecdsa_aspeed.c
	    ${HROT_MIDDLEWARE_ROOT}/i2c/i2c_filter_aspeed.c
	    ${HROT_MIDDLEWARE_ROOT}/i2c/I2C_Slave_aspeed.c
	    ${HROT_MIDDLEWARE_ROOT}/watchdog/watchdog_aspeed.c
	    ${HROT_MIDDLEWARE_ROOT}/otp/otp_aspeed.c
	    ${HROT_MIDDLEWARE_ROOT}/abr/abr_aspeed.c
	    ${HROT_MIDDLEWARE_ROOT}/spi_filter/spi_filter_aspeed.c
	)
	zephyr_library_include_directories(	
	    .
	    $ENV{ZEPHYR_BASE}/build/zephyr/include/generated/
	    $ENV{ZEPHYR_BASE}/include/storage/
	)
	
	zephyr_library_link_libraries(hrot_middleware)

endif()