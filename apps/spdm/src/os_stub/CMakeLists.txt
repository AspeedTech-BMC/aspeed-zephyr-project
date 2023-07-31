
zephyr_include_directories(cryptlib_mbedtls)
zephyr_include_directories(include)
zephyr_include_directories(spdm_device_secret_lib_zephyr)
# zephyr_include_directories(mbedtlslib/include)

target_sources(app PRIVATE
	# cryptlib_mbedtls

	debuglib_zephyr/debuglib.c

	malloclib/malloclib.c

	# mbedtlslib

	platform_lib_zephyr/time_zephyr.c
	platform_lib_zephyr/watchdog.c

	rnglib/rng_zephyr.c

	spdm_device_secret_lib_zephyr/lib.c
	spdm_device_secret_lib_zephyr/cert.c
	)
