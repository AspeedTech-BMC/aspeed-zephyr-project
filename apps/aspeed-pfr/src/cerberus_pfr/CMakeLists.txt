# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

target_sources(app PRIVATE
	cerberus_pfr_authentication.c
	cerberus_pfr_provision.c
	cerberus_pfr_update.c
	cerberus_pfr_common.c
	cerberus_pfr_recovery.c
	cerberus_pfr_verification.c
	cerberus_pfr_key_cancellation.c
	cerberus_pfr_smbus_filtering.c
	cerberus_pfr_spi_filtering.c
	cerberus_pfr_svn.c
	cerberus_pfr_key_manifest.c
	)

if(CONFIG_SHELL)
        target_sources(app PRIVATE test_cerberus_pfr_shell.c)
endif()
