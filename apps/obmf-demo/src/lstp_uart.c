/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/irq.h>
#include <zephyr/logging/log.h>

#include "lstp_router.h"
#include "lstp_uart.h"

LOG_MODULE_REGISTER(lstp_uart, LOG_LEVEL_ERR);

static const struct device *lstp_uart3_dev;

static bool lstp_uart_host_active;

static void lstp_uart_forward_rx_bytes(const uint8_t *data, size_t len)
{
	int ret;

	if (!lstp_uart_host_active || len == 0U) {
		return;
	}

	ret = lstp_router_send_uart_data(data, len);
	if (ret < 0) {
		LOG_WRN("Failed to forward UART RX data: %d", ret);
	}
}

void lstp_uart_set_host_active(bool active)
{
	unsigned int key = irq_lock();

	lstp_uart_host_active = active;

	irq_unlock(key);
}

void shell_uart_mirror_tx_hook(const uint8_t *data, size_t len)
{
	ARG_UNUSED(data);
	ARG_UNUSED(len);
}

static void lstp_uart3_irq_handler(const struct device *dev, void *user_data)
{
	uint8_t buf[64];

	ARG_UNUSED(user_data);

	if (!uart_irq_update(dev)) {
		return;
	}

	while (uart_irq_rx_ready(dev)) {
		int rd = uart_fifo_read(dev, buf, sizeof(buf));

		if (rd <= 0) {
			break;
		}

		lstp_uart_forward_rx_bytes(buf, rd);
	}
}

int lstp_uart_init(void)
{
	lstp_uart3_dev = DEVICE_DT_GET(DT_NODELABEL(uart3));
	if (!device_is_ready(lstp_uart3_dev)) {
		LOG_ERR("uart3 device not ready");
		return -ENODEV;
	}

	uart_irq_callback_set(lstp_uart3_dev, lstp_uart3_irq_handler);
	uart_irq_rx_enable(lstp_uart3_dev);
	return 0;
}

lstp_status_t lstp_uart_receive(uint8_t channel_id,
				struct lstp_hdr *hdr,
				uint8_t *payload, size_t payload_len,
				uint8_t *resp_payload, size_t *resp_payload_len)
{
	lstp_uart_command_t cmd;

	ARG_UNUSED(channel_id);
	ARG_UNUSED(resp_payload);

	*resp_payload_len = 0;

	cmd = (lstp_uart_command_t)(hdr->cmd_status_code & ~LSTP_RESPONSE_BIT);
	if (cmd != LSTP_UART_CMD_WRITE) {
		return LSTP_STATUS_NOT_SUPPORTED;
	}

	/* No payload = connection open signal, mark host side active. */
	if (payload_len == 0U) {
		lstp_uart_host_active = true;
	}
	/* Has payload = TX data from host, send to uart3. */
	else if (lstp_uart3_dev != NULL && payload != NULL) {
		lstp_uart_host_active = true;
		for (size_t i = 0; i < payload_len; i++) {
			uart_poll_out(lstp_uart3_dev, payload[i]);
		}
	}

	return LSTP_STATUS_SUCCESS;
}
