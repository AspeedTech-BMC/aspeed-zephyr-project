/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LSTP_CHANNEL_H
#define LSTP_CHANNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/sys/iterable_sections.h>

#include "lstp_common.h"

/*
 * An exported LSTP channel. Each channel module defines one with
 * LSTP_CHANNEL_DEFINE(); the router and task find it by ID, so the core never
 * names a channel module. The management channel (ID 0) belongs to the router
 * and is not defined this way.
 */
struct lstp_channel {
	/* LSTP_*_CHANNEL_ID; LSTP_CHANNEL_ID_NONE leaves the channel out. */
	uint8_t id;
	lstp_channel_type_t type;
	const char *name;

	/* Optional. Called once from lstp_router_init(); failures are logged. */
	int (*init)(void);

	/*
	 * Optional. Append the type-specific part of the channel config blob to
	 * buf (cap bytes free) and set *len. Without it the blob ends after the
	 * common header. Runs in the USB controller ISR, as does config_written:
	 * both must be ISR-safe and must not block.
	 */
	lstp_status_t (*read_config)(const struct lstp_channel_config_read_request *req,
				     uint8_t *buf, size_t cap, size_t *len);

	/* Optional, ISR context. Called after the host writes a matching config blob. */
	void (*config_written)(void);

	/*
	 * Handle one request in the LSTP task thread, where blocking is allowed.
	 * Fill resp_payload and *resp_payload_len; clear *send_response for
	 * requests that take no reply.
	 */
	lstp_status_t (*receive)(uint8_t channel_id, struct lstp_hdr *hdr,
				 uint8_t *payload, size_t payload_len,
				 uint8_t *resp_payload, size_t *resp_payload_len,
				 bool *send_response);

	/* Optional. Called by the task thread after each request and on lstp_task_kick(). */
	void (*poll)(void);

	/*
	 * Optional, ISR context. The USB host went away (reset, unconfigure or
	 * disconnect): drop per-host state so nothing of it reaches the next host.
	 */
	void (*host_reset)(void);
};

#define LSTP_CHANNEL_DEFINE(_name, ...) \
	static const STRUCT_SECTION_ITERABLE(lstp_channel, _name) = { __VA_ARGS__ }

#endif /* LSTP_CHANNEL_H */
