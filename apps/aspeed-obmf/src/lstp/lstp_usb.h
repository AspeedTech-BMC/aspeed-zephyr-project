/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

#ifndef LSTP_USB_H
#define LSTP_USB_H

#include <zephyr/kernel.h>

#include <stdint.h>
#include <stddef.h>

#define LSTP_IN_EP_ADDR  0x81
#define LSTP_OUT_EP_ADDR 0x01

/* LSTP USB Buffer max size (Must be 512 for High-Speed USB Bulk Endpoints) */
#define LSTP_USB_MAX_EP_BUFFER_SIZE 512

int lstp_usb_init(void);

/* Queue a USB response. ISR callers never block; timeout applies only in thread context. */
int lstp_usb_send_response(const uint8_t *data, size_t len, k_timeout_t timeout);

/*
 * USB session: bumped on every reset, unconfigure and disconnect. A request
 * remembers the session it arrived in; its response is queued only if that
 * session is still current (-ESTALE otherwise).
 */
uint32_t lstp_usb_session(void);

/* Re-arm the OUT endpoint if it was paused for a full task queue (task thread). */
void lstp_usb_rx_resume(void);
int lstp_usb_send_response_in(uint32_t session, const uint8_t *data, size_t len,
			      k_timeout_t timeout);

int lstp_usb_send_event(const uint8_t *data, size_t len);
int lstp_usb_send_event_in(uint32_t session, const uint8_t *data, size_t len);

struct lstp_hdr;

/* Queue an event as hdr + payload without building it on the caller's stack. */
int lstp_usb_send_event_parts(const struct lstp_hdr *hdr, const void *payload,
			      size_t payload_len);

struct lstp_usb_stats {
	uint32_t response_drops;
	uint32_t event_drops;
	uint32_t rx_drops;
	uint32_t write_errors;
	uint32_t tx_high_water;
};

void lstp_usb_get_stats(struct lstp_usb_stats *stats);

#endif /* LSTP_USB_H */
