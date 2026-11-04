# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

# LSTP core: USB transport, router, task thread. Channel modules register with
# LSTP_CHANNEL_DEFINE() into the section added here.
zephyr_linker_sources(SECTIONS lstp_channels.ld)

target_sources(app PRIVATE
    lstp_usb.c
    lstp_router.c
    lstp_task.c
)

# Firmware-initiated requests; the remote MTD client is the only user.
target_sources_ifdef(CONFIG_OBMF_LSTP_MTD_CLIENT app PRIVATE lstp_transaction.c)
