# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

# Generate aspeed-zephyr-project version header
execute_process(
  COMMAND bash -c "git tag --sort=-v:refname | head -n 1"
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE ASPEED_ZEPHYR_PROJECT_TAG
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)
execute_process(
  COMMAND git rev-parse --short HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE ASPEED_ZEPHYR_PROJECT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)
execute_process(
  COMMAND bash -c "git diff --quiet || echo dirty-"
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE ASPEED_ZEPHYR_PROJECT_DIRTY
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)
execute_process(
  COMMAND bash -c "date '+%Y-%m-%d %H:%M:%S'"
  OUTPUT_VARIABLE ASPEED_ZEPHYR_PROJECT_BUILD_TIMESTAMP
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(ASPEED_ZEPHYR_PROJECT_VERSION "${ASPEED_ZEPHYR_PROJECT_TAG}-${ASPEED_ZEPHYR_PROJECT_DIRTY}${ASPEED_ZEPHYR_PROJECT_HASH}")
set(ASPEED_ZEPHYR_PROJECT_VERSION_HEADER "${CMAKE_BINARY_DIR}/aspeed_zephyr_project_version.h")
set(ASPEED_ZEPHYR_PROJECT_VERSION_HEADER_CONTENT "#ifndef ASPEED_ZEPHYR_PROJECT_VERSION_H\n#define ASPEED_ZEPHYR_PROJECT_VERSION_H\n\n#define ASPEED_ZEPHYR_PROJECT_VERSION \"${ASPEED_ZEPHYR_PROJECT_VERSION}\"\n#define ASPEED_ZEPHYR_PROJECT_BUILD_TIMESTAMP \"${ASPEED_ZEPHYR_PROJECT_BUILD_TIMESTAMP}\"\n\n#endif // ASPEED_ZEPHYR_PROJECT_VERSION_H\n")
file(WRITE ${ASPEED_ZEPHYR_PROJECT_VERSION_HEADER} "${ASPEED_ZEPHYR_PROJECT_VERSION_HEADER_CONTENT}")
if(TARGET app)
  target_include_directories(app PRIVATE ${CMAKE_BINARY_DIR})
endif()

target_sources(app PRIVATE main.c)

# Common layer
add_subdirectory(AspeedStateMachine)
add_subdirectory(common)
add_subdirectory(include)
add_subdirectory(engineManager)
add_subdirectory(manifestProcessor)
add_subdirectory(pfr)
add_subdirectory(platform_monitor)
add_subdirectory(Smbus_mailbox)
add_subdirectory(spi_filter)
add_subdirectory(watchdog_timer)
add_subdirectory(otp)
add_subdirectory(i2c)
add_subdirectory(i3c)

# Vendor specific layer
add_subdirectory_ifdef(CONFIG_INTEL_PFR intel_pfr)
add_subdirectory_ifdef(CONFIG_CERBERUS_PFR cerberus_pfr)

# Features
add_subdirectory_ifdef(CONFIG_PFR_MCTP mctp)
if(DEFINED CONFIG_PFR_SPDM_ATTESTATION OR DEFINED CONFIG_PFR_SPDM_RESPONDER)
    add_subdirectory(SPDM)
endif()