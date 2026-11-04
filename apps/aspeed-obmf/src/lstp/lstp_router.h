/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

#ifndef LSTP_ROUTER_H
#define LSTP_ROUTER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct lstp_channel;

/* Collect the LSTP_CHANNEL_DEFINE() channels and initialize them. */
void lstp_router_init(void);

/* Return the channel exported under channel_id, or NULL. */
const struct lstp_channel *lstp_router_channel(uint8_t channel_id);

/* Route one host packet; negative when it was dropped. */
int lstp_router_receive(uint8_t *buffer, size_t len);

/* True once the host has sent a request since the last USB reset. */
bool lstp_router_host_active(void);

/* Forget the host session on USB reset or disconnect. */
void lstp_router_host_reset(void);

/* Send an unsolicited LSTP packet; -ENOTSUP if channel_id is not exported. */
int lstp_router_send_event(uint8_t channel_id, uint8_t command, const void *data, size_t len);

#endif /* LSTP_ROUTER_H */
