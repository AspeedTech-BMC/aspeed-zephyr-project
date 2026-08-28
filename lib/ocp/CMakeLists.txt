# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

if (CONFIG_BMC_COMPOSITE_EAT_SDK)
zephyr_interface_library_named(bmc_composite_eat_sdk)

target_include_directories(bmc_composite_eat_sdk INTERFACE
	bmc-composite-eat-sdk/include
)

zephyr_library()

zephyr_library_sources(
	bmc-composite-eat-sdk/third_party/qcbor/src/UsefulBuf.c
        bmc-composite-eat-sdk/third_party/qcbor/src/ieee754.c
        bmc-composite-eat-sdk/third_party/qcbor/src/qcbor_decode.c
        bmc-composite-eat-sdk/third_party/qcbor/src/qcbor_encode.c
        bmc-composite-eat-sdk/third_party/qcbor/src/qcbor_err_to_str.c
)
target_include_directories(
	bmc_composite_eat_sdk INTERFACE
        bmc-composite-eat-sdk/third_party/qcbor/inc
        bmc-composite-eat-sdk/third_party/qcbor/inc/qcbor
)

target_compile_definitions(
	bmc_composite_eat_sdk INTERFACE
        QCBOR_DISABLE_FLOAT_HW_USE
        QCBOR_DISABLE_PREFERRED_FLOAT
        USEFULBUF_DISABLE_ALL_FLOAT
        QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
        QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS	
)

zephyr_library_sources(
	bmc-composite-eat-sdk/src/generation_request.c
	bmc-composite-eat-sdk/src/types.c
	bmc-composite-eat-sdk/src/token_builder.c
)

target_include_directories(
	bmc_composite_eat_sdk INTERFACE
	bmc-composite-eat-sdk/include
)

zephyr_library_link_libraries(bmc_composite_eat_sdk)

endif()

