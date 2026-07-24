# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT
target_sources(app PRIVATE
	pfr_common.c
	pfr_recovery.c
	pfr_ufm.c
	pfr_update.c
	pfr_util.c
	pfr_verification.c
	)
# No-op ABR API stubs for SoCs without an ABR driver yet (e.g. AST1080/G2).
# Self-guarded with !CONFIG_ABR_FLOW_CTRL_ASPEED, so it compiles to nothing
# when the real driver is present.
target_sources(app PRIVATE abr_stub.c)
