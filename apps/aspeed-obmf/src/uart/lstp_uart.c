/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

/*
 * Parts of the LSTP UART channel that do not depend on how the host UART is
 * reached. The other half lives in lstp_uart_vuart.c, lstp_uart_plain.c or
 * lstp_uart_shell.c; see lstp_uart_backend.h.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include "lstp/lstp_backend.h"
#include "lstp/lstp_channel.h"
#include "lstp/lstp_router.h"
#include "lstp_uart.h"
#include "lstp_uart_backend.h"

LOG_MODULE_REGISTER(lstp_uart, LOG_LEVEL_ERR);

/* Reported to the host: the backend UART's DT current-speed (the shell backend has none). */
#define LSTP_UART_BAUD \
	COND_CODE_1(DT_NODE_HAS_PROP(LSTP_BACKEND_NODE, uart_controller), \
		    (DT_PROP_OR(LSTP_UART_NODE, current_speed, 115200)), (115200))

bool lstp_uart_host_active = true;
atomic_t lstp_uart_rx_dropped_bytes;
atomic_t lstp_uart_rx_fifo_overruns;
atomic_t lstp_uart_tx_dropped_bytes;
atomic_t lstp_uart_tx_nak_events;
atomic_t lstp_uart_rx_forward_dropped_bytes;

int lstp_uart_send_to_host(const uint8_t *data, size_t len)
{
	return lstp_router_send_event(LSTP_UART_CHANNEL_ID, LSTP_UART_CMD_WRITE, data, len);
}

static void lstp_uart_set_host_active(bool active)
{
	unsigned int key = irq_lock();

	lstp_uart_host_active = active;

	irq_unlock(key);
	if (active) {
		lstp_uart_resume_forwarding();
	}
}

void lstp_uart_get_stats(struct lstp_uart_stats *stats)
{
	if (stats == NULL) {
		return;
	}
	stats->rx_dropped_bytes = atomic_get(&lstp_uart_rx_dropped_bytes);
	stats->rx_fifo_overruns = atomic_get(&lstp_uart_rx_fifo_overruns);
	stats->tx_dropped_bytes = atomic_get(&lstp_uart_tx_dropped_bytes);
	stats->rx_forward_dropped_bytes = atomic_get(&lstp_uart_rx_forward_dropped_bytes);
	stats->tx_nak_events = atomic_get(&lstp_uart_tx_nak_events);
}

static lstp_status_t lstp_uart_receive(uint8_t channel_id,
				       struct lstp_hdr *hdr,
				       uint8_t *payload, size_t payload_len,
				       uint8_t *resp_payload, size_t *resp_payload_len,
				       bool *send_response)
{
	lstp_uart_command_t cmd;

	ARG_UNUSED(channel_id);
	ARG_UNUSED(resp_payload);
	ARG_UNUSED(send_response);

	*resp_payload_len = 0;

	cmd = (lstp_uart_command_t)(hdr->cmd_status_code & ~LSTP_RESPONSE_BIT);
	if (cmd != LSTP_UART_CMD_WRITE) {
		return LSTP_STATUS_NOT_SUPPORTED;
	}

	if (payload_len == 0U) {
		lstp_uart_set_host_active(true);
	} else if (payload != NULL) {
		lstp_uart_set_host_active(true);

		/* VUART and shell backends NAK when full; the plain one blocks instead. */
		int ret = lstp_uart_tx_bytes(payload, payload_len);

		if (ret == -EBUSY) {
			return LSTP_STATUS_NAK;
		}
		if (ret < 0) {
			return LSTP_STATUS_ERROR;
		}
	}

	return LSTP_STATUS_SUCCESS;
}

static lstp_status_t lstp_uart_read_config(const struct lstp_channel_config_read_request *req,
					   uint8_t *buf, size_t cap, size_t *len)
{
	struct lstp_uart_channel_config *uart_cfg = (struct lstp_uart_channel_config *)buf;

	if (req->offset == 0U && req->length == 0U) {
		lstp_uart_set_host_active(true);
	}

	*len = 0;
	if (sizeof(*uart_cfg) <= cap) {
		uart_cfg->speed = sys_cpu_to_le32(LSTP_UART_BAUD);
		uart_cfg->data_bits = 8;
		uart_cfg->stop_bits = 1;
		uart_cfg->parity_flow = 0;
		*len = sizeof(*uart_cfg);
	}
	return LSTP_STATUS_SUCCESS;
}

static void lstp_uart_config_written(void)
{
	lstp_uart_set_host_active(true);
}

/*
 * Drop what was buffered for the old host. Forwarding itself keeps running:
 * the host driver does not rewrite the channel config after re-enumerating,
 * so a reader that only opens the tty would otherwise never get data again.
 */
static void lstp_uart_host_reset(void)
{
	lstp_uart_backend_host_reset();
}

LSTP_CHANNEL_DEFINE(lstp_uart_channel,
	.id = LSTP_UART_CHANNEL_ID,
	.type = LSTP_CHANNEL_TYPE_UART,
	.name = LSTP_UART_CHANNEL_NAME,
	.init = lstp_uart_init,
	.read_config = lstp_uart_read_config,
	.config_written = lstp_uart_config_written,
	.receive = lstp_uart_receive,
	.host_reset = lstp_uart_host_reset,
);
