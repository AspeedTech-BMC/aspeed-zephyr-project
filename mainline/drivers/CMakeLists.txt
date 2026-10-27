# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

# Drivers mcu-runtime needs on the AST2700 BootMCU that upstream Zephyr does
# not provide. Each subdirectory owns its own CMakeLists.txt and Kconfig.
file(GLOB driver_dirs LIST_DIRECTORIES true ${CMAKE_CURRENT_SOURCE_DIR}/*)
foreach(dir ${driver_dirs})
  if(EXISTS ${dir}/CMakeLists.txt)
    add_subdirectory(${dir})
  endif()
endforeach()
