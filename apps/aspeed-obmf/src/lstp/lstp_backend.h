/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LSTP_BACKEND_H
#define LSTP_BACKEND_H

#include <stdint.h>

#include <zephyr/devicetree.h>
#include <zephyr/sys/util.h>

#include "lstp_common.h"

#define LSTP_BACKEND_NODE DT_COMPAT_GET_ANY_STATUS_OKAY(aspeed_obmf_lstp)

#if !DT_NODE_EXISTS(LSTP_BACKEND_NODE)
#error "aspeed-obmf requires an enabled aspeed,obmf-lstp topology node"
#endif

#define LSTP_UART_NODE DT_PHANDLE(LSTP_BACKEND_NODE, uart_controller)

#define LSTP_UART_CHANNEL_NAME DT_PROP(LSTP_BACKEND_NODE, uart_channel_name)

#define LSTP_HAS_UART_CHANNEL 1

/* Keep channel IDs dense: the BMC enumerates 1..num_channels. */
#define LSTP_MGMT_CHANNEL_ID 0U
#define LSTP_SLOT_UART       (LSTP_MGMT_CHANNEL_ID + 1U)

#define LSTP_NUM_CHANNELS    (LSTP_SLOT_UART + LSTP_HAS_UART_CHANNEL)

/* Never a valid channel ID; the ID of every channel the topology leaves out. */
#define LSTP_CHANNEL_ID_NONE 0xFFU

#define LSTP_UART_CHANNEL_ID (LSTP_HAS_UART_CHANNEL ? LSTP_SLOT_UART : LSTP_CHANNEL_ID_NONE)

/* An exported channel needs the topology fields that describe it. */
#if !IS_ENABLED(CONFIG_OBMF_LSTP_UART_SHELL) && \
	!DT_NODE_HAS_PROP(LSTP_BACKEND_NODE, uart_controller)
#error "The UART channel requires uart-controller unless CONFIG_OBMF_LSTP_UART_SHELL"
#endif

BUILD_ASSERT(LSTP_NUM_CHANNELS <= LSTP_CHANNEL_ID_NONE,
	     "LSTP channel IDs must stay distinct from LSTP_CHANNEL_ID_NONE");

#endif /* LSTP_BACKEND_H */
