/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

#ifndef LSTP_UART_H
#define LSTP_UART_H

#include <stddef.h>
#include <stdint.h>

#include "lstp/lstp_common.h"

#define LSTP_UART_MIRROR_BUF_SIZE (4 * LSTP_MAX_PAYLOAD_SIZE)

/* Write bytes to the host UART; -EBUSY asks the caller to retry later. */
int lstp_uart_tx_bytes(const uint8_t *data, size_t len);

/* Send host UART output to the BMC as an LSTP UART event. */
int lstp_uart_send_to_host(const uint8_t *data, size_t len);

struct lstp_uart_stats {
	uint32_t rx_dropped_bytes;
	uint32_t tx_dropped_bytes;
	uint32_t rx_fifo_overruns;
	uint32_t rx_forward_dropped_bytes;
	uint32_t tx_nak_events;
};

void lstp_uart_get_stats(struct lstp_uart_stats *stats);

#endif /* LSTP_UART_H */
