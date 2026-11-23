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
	intel_pfr_sig_scheme.c
	intel_pfr_sig_ecdsa.c
	)

zephyr_linker_sources(SECTIONS intel_pfr_sig_scheme.ld)
target_sources_ifdef(CONFIG_MBEDTLS_LMS_C app PRIVATE intel_pfr_sig_lms.c)
target_sources_ifdef(CONFIG_PFR_SIG_P384_MLDSA87 app PRIVATE intel_pfr_sig_hybrid.c)

if(CONFIG_INTEL_PFR_CPLD_UPDATE)
        target_sources(app PRIVATE intel_pfr_cpld_utils.c)
endif()

if(CONFIG_SHELL)
        target_sources(app PRIVATE test_intel_pfr_shell.c)
endif()
