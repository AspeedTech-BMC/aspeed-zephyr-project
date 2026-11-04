# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

target_sources(app PRIVATE lstp_mtd_client.c)
target_sources_ifdef(CONFIG_SHELL app PRIVATE lstp_mtd_shell.c)
