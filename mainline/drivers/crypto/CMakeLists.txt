# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_CPTRA_ECDSA OR CONFIG_CPTRA_LMS OR CONFIG_CPTRA_SHA)
  zephyr_library()
  zephyr_library_sources_ifdef(CONFIG_CPTRA_ECDSA cptra_ecdsa.c)
  zephyr_library_sources_ifdef(CONFIG_CPTRA_LMS cptra_lms.c)
  zephyr_library_sources_ifdef(CONFIG_CPTRA_SHA cptra_sha.c)
endif()
