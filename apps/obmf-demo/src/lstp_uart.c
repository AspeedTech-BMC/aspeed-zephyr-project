/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <zephyr/device.h>
#include <zephyr/drivers/console/uart_console.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>

#include "lstp_router.h"
#include "lstp_uart.h"

LOG_MODULE_REGISTER(lstp_uart, LOG_LEVEL_ERR);

static const struct device *lstp_uart3_dev;

static bool lstp_uart_host_active;
static bool lstp_uart_tx_busy;
static bool lstp_uart_in_esc;
static bool lstp_uart_in_csi;
static char lstp_uart_tx_buf[LSTP_UART_MIRROR_BUF_SIZE];
static size_t lstp_uart_tx_len;
static char lstp_uart_send_buf[LSTP_UART_MIRROR_BUF_SIZE];
static size_t lstp_uart_send_len;

static void lstp_uart_flush_tx_buf(void)
{
	unsigned int key = irq_lock();

	if (!lstp_uart_host_active || lstp_uart_tx_busy || lstp_uart_tx_len == 0U) {
		irq_unlock(key);
		return;
	}

	lstp_uart_tx_busy = true;
	/* Copy to send buffer while holding lock */
	memcpy(lstp_uart_send_buf, lstp_uart_tx_buf, lstp_uart_tx_len);
	lstp_uart_send_len = lstp_uart_tx_len;
	lstp_uart_tx_len = 0U;

	irq_unlock(key);

	/* Send outside of IRQ lock to prevent blocking interrupts */
	int ret = lstp_router_send_uart_data((const uint8_t *)lstp_uart_send_buf, lstp_uart_send_len);
	if (ret < 0) {
		LOG_WRN("Failed to send UART data: %d", ret);
	}

	key = irq_lock();
	lstp_uart_tx_busy = false;
	irq_unlock(key);
}

static bool lstp_uart_filter_tx_char(char c)
{
	if (lstp_uart_in_esc) {
		lstp_uart_in_esc = false;
		if (c == '[') {
			lstp_uart_in_csi = true;
		}
		return false;
	}

	if (lstp_uart_in_csi) {
		if ((c >= '@' && c <= '~') || c == '\0') {
			lstp_uart_in_csi = false;
		}
		return false;
	}

	if ((unsigned char)c == 0x1bU) {
		lstp_uart_in_esc = true;
		return false;
	}

	return true;
}

static void lstp_uart_mirror_tx_bytes(const uint8_t *data, size_t len)
{
	unsigned int key = irq_lock();

	if (!lstp_uart_host_active) {
		lstp_uart_tx_len = 0U;
		lstp_uart_in_esc = false;
		lstp_uart_in_csi = false;
		irq_unlock(key);
		return;
	}

	for (size_t i = 0; i < len; i++) {
		char c = (char)data[i];

		if (!lstp_uart_filter_tx_char(c)) {
			continue;
		}

		if (c == '\r') {
			continue;
		}

		if (lstp_uart_tx_len < sizeof(lstp_uart_tx_buf)) {
			lstp_uart_tx_buf[lstp_uart_tx_len++] = c;
		} else {
			/* Buffer full, flush and retry if possible */
			LOG_WRN("TX buffer full, flushing");
			lstp_uart_flush_tx_buf();
			if (lstp_uart_tx_len < sizeof(lstp_uart_tx_buf)) {
				lstp_uart_tx_buf[lstp_uart_tx_len++] = c;
			}
		}

		if (c == '\n' || lstp_uart_tx_len == sizeof(lstp_uart_tx_buf)) {
			lstp_uart_flush_tx_buf();
		}
	}

	irq_unlock(key);
}

static UART_CONSOLE_OUT_DEBUG_HOOK_SIG(lstp_uart_console_out_hook)
{
	uint8_t byte = (uint8_t)c;

	lstp_uart_mirror_tx_bytes(&byte, 1U);
	return 0;
}

void lstp_uart_set_host_active(bool active)
{
	unsigned int key = irq_lock();

	lstp_uart_host_active = active;
	lstp_uart_tx_busy = false;
	lstp_uart_tx_len = 0U;
	lstp_uart_in_esc = false;
	lstp_uart_in_csi = false;

	irq_unlock(key);
}

void shell_uart_mirror_tx_hook(const uint8_t *data, size_t len)
{
	if (data == NULL || len == 0U) {
		return;
	}

	lstp_uart_mirror_tx_bytes(data, len);
}

static void lstp_uart3_irq_handler(const struct device *dev, void *user_data)
{
	uint8_t buf[64];

	ARG_UNUSED(user_data);

	if (!uart_irq_update(dev)) {
		return;
	}

	/* Drain RX FIFO to prevent buffer full, but don't send to host */
	while (uart_irq_rx_ready(dev)) {
		if (uart_fifo_read(dev, buf, sizeof(buf)) <= 0) {
			break;
		}
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

	uart_console_out_debug_hook_install(lstp_uart_console_out_hook);
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

	/* No payload = connection open signal, enable TX mirror for cat to receive console output */
	if (payload_len == 0U) {
		lstp_uart_host_active = true;
	}
	/* Has payload = RX data from host, send to uart3 */
	else if (lstp_uart3_dev != NULL && payload != NULL) {
		lstp_uart_host_active = true;
		for (size_t i = 0; i < payload_len; i++) {
			uart_poll_out(lstp_uart3_dev, payload[i]);
		}
	}

	return LSTP_STATUS_SUCCESS;
}
