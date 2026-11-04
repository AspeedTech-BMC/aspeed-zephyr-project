# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

target_sources(app PRIVATE
    espi_bridge.c
    espi_oob_bridge.c
    safs_handler.c
)
target_sources_ifdef(CONFIG_SHELL app PRIVATE espi_shell.c)

target_sources_ifdef(CONFIG_OBMF_ESPI_MMIO app PRIVATE lstp_mmio.c)
target_sources_ifdef(CONFIG_OBMF_ESPI_IPMI app PRIVATE espi_mmbi.c)
