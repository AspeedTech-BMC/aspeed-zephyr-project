# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT
target_sources(app PRIVATE
	intel_pfr_authentication.c
	intel_pfr_pfm_manifest.c
	intel_pfr_spi_filtering.c
	intel_pfr_key_cancellation.c
	intel_pfr_provision.c
	intel_pfr_update.c
	intel_pfr_pbc.c
	intel_pfr_recovery.c
	intel_pfr_verification.c
	intel_pfr_svn.c
	)
