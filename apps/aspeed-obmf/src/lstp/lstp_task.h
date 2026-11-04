/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

#ifndef LSTP_TASK_H
#define LSTP_TASK_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/*
 * ISR-safe: copy the request to the task queue for blocking peripheral operations.
 * resp_channel_id is the channel the reply goes out on.
 */
int lstp_task_submit_req(uint8_t *buffer, size_t len, uint8_t resp_channel_id);

/* ISR-safe: wake the task so it runs every channel's poll hook. */
void lstp_task_kick(void);

/*
 * ISR-safe. Drop every queued request: they belong to a host that went away,
 * and must not take the slots the next host's first requests need.
 */
void lstp_task_drop_requests(void);

/* True when no further request fits; the USB OUT endpoint then stops accepting. */
bool lstp_task_queue_full(void);

#endif /* LSTP_TASK_H */
