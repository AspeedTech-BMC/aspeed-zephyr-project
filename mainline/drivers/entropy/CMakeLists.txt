# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_ENTROPY_ASPEED_TRNG OR CONFIG_ENTROPY_ASPEED_NISTTRNG)
  zephyr_library_amend()
  zephyr_library_sources_ifdef(CONFIG_ENTROPY_ASPEED_TRNG entropy_aspeed_trng.c)
  zephyr_library_sources_ifdef(CONFIG_ENTROPY_ASPEED_NISTTRNG entropy_aspeed_nisttrng.c)
endif()
