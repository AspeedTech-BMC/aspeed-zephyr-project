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
 * LSTP UART backend that drives the ordinary UART named by the
 * aspeed,obmf-lstp uart-controller phandle, buffering RX in a ring that a
 * delayable work item drains onto the router. Built unless
 * CONFIG_OBMF_LSTP_UART_SHELL is set.
 */

#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/irq.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/sys/util.h>

#include "lstp/lstp_backend.h"
#include "lstp_uart.h"
#include "lstp_uart_backend.h"

LOG_MODULE_DECLARE(lstp_uart, LOG_LEVEL_ERR);

#define LSTP_UART_DRAIN_DELAY K_MSEC(5)
#define LSTP_UART_DRAIN_RETRY_DELAY K_MSEC(10)

static const struct device *lstp_uart_dev;

RING_BUF_DECLARE(lstp_uart_rx_ring, LSTP_UART_MIRROR_BUF_SIZE);
static struct k_work_delayable lstp_uart_rx_drain_work;
static uint8_t lstp_uart_tx_pending[LSTP_MAX_PAYLOAD_SIZE];
static size_t lstp_uart_tx_pending_len;
static uint32_t lstp_uart_rx_overflow_bytes_reported;
/* Set on host reset: the drain drops the chunk it had taken for the old host. */
static atomic_t lstp_uart_rx_flush;

static void lstp_uart_rx_drop_oldest(size_t len)
{
	uint8_t drop_buf[64];

	while (len > 0U) {
		uint32_t drop_len = MIN(len, sizeof(drop_buf));
		uint32_t dropped = ring_buf_get(&lstp_uart_rx_ring, drop_buf, drop_len);

		if (dropped == 0U) {
			break;
		}

		atomic_add(&lstp_uart_rx_dropped_bytes, dropped);
		len -= dropped;
	}
}

static void lstp_uart_report_rx_overflow(void)
{
	uint32_t overflow_bytes;
	uint32_t dropped_bytes;
	unsigned int key;

	key = irq_lock();
	overflow_bytes = atomic_get(&lstp_uart_rx_dropped_bytes);
	irq_unlock(key);

	if (overflow_bytes == lstp_uart_rx_overflow_bytes_reported) {
		return;
	}

	dropped_bytes = overflow_bytes - lstp_uart_rx_overflow_bytes_reported;
	lstp_uart_rx_overflow_bytes_reported = overflow_bytes;
	LOG_WRN("UART RX ring overflow, dropped oldest %u bytes", dropped_bytes);
}

static void lstp_uart_rx_buffer_put(const uint8_t *data, size_t len)
{
	uint32_t remaining;
	uint32_t written;

	if (len > LSTP_UART_MIRROR_BUF_SIZE) {
		data += len - LSTP_UART_MIRROR_BUF_SIZE;
		len = LSTP_UART_MIRROR_BUF_SIZE;
	}

	remaining = len;
	while (remaining > 0U) {
		written = ring_buf_put(&lstp_uart_rx_ring, data, remaining);
		if (written == remaining) {
			return;
		}

		data += written;
		remaining -= written;

		lstp_uart_rx_drop_oldest(remaining);
	}
}

static void lstp_uart_rx_drain(struct k_work *work)
{
	int ret;
	uint32_t len;

	ARG_UNUSED(work);

	if (atomic_cas(&lstp_uart_rx_flush, 1, 0)) {
		atomic_add(&lstp_uart_rx_forward_dropped_bytes,
			   (atomic_val_t)lstp_uart_tx_pending_len);
		lstp_uart_tx_pending_len = 0U;
	}

	if (!lstp_uart_host_active) {
		return;
	}

	lstp_uart_report_rx_overflow();

	if (lstp_uart_tx_pending_len == 0U) {
		unsigned int key = irq_lock();

		len = ring_buf_get(&lstp_uart_rx_ring, lstp_uart_tx_pending,
				   sizeof(lstp_uart_tx_pending));
		irq_unlock(key);

		lstp_uart_tx_pending_len = len;
		if (lstp_uart_tx_pending_len == 0U) {
			return;
		}
	}

	len = lstp_uart_tx_pending_len;
	ret = lstp_uart_send_to_host(lstp_uart_tx_pending,
				     lstp_uart_tx_pending_len);
	if (ret == -ENOSPC || ret == -EBUSY) {
		/* USB event queue full: keep the chunk and retry shortly. */
		k_work_reschedule(&lstp_uart_rx_drain_work,
				  LSTP_UART_DRAIN_RETRY_DELAY);
		return;
	}
	if (ret < 0) {
		/*
		 * No host (unplugged, unconfigured or reset): drop the chunk so it
		 * never reaches the next host, and stop; the next RX byte restarts
		 * the drain, so nothing polls while the cable is out.
		 */
		atomic_add(&lstp_uart_rx_forward_dropped_bytes, (atomic_val_t)len);
		lstp_uart_tx_pending_len = 0U;
		return;
	}

	lstp_uart_tx_pending_len = 0U;

	if (len == sizeof(lstp_uart_tx_pending)) {
		k_work_reschedule(&lstp_uart_rx_drain_work, LSTP_UART_DRAIN_DELAY);
	}
}

static void lstp_uart_forward_rx_bytes(const uint8_t *data, size_t len)
{
	unsigned int key;
	int ret;

	if (len == 0U) {
		return;
	}

	key = irq_lock();
	lstp_uart_rx_buffer_put(data, len);
	irq_unlock(key);
	if (!lstp_uart_host_active) {
		return;
	}

	/*
	 * Schedule, not reschedule: a continuous stream would otherwise keep
	 * pushing the drain out until the ring wraps and drops all but its tail.
	 */
	ret = k_work_schedule(&lstp_uart_rx_drain_work, LSTP_UART_DRAIN_DELAY);
	if (ret < 0) {
		LOG_WRN("Failed to schedule UART RX drain: %d", ret);
	}
}

static void lstp_uart_irq_handler(const struct device *dev, void *user_data)
{
	uint8_t buf[64];

	ARG_UNUSED(user_data);

	if (!uart_irq_update(dev)) {
		return;
	}

	if (uart_err_check(dev) & UART_ERROR_OVERRUN) {
		atomic_inc(&lstp_uart_rx_fifo_overruns);
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
	lstp_uart_dev = DEVICE_DT_GET(LSTP_UART_NODE);
	if (!device_is_ready(lstp_uart_dev)) {
		LOG_ERR("UART backend %s not ready", LSTP_UART_CHANNEL_NAME);
		lstp_uart_dev = NULL;
		return -ENODEV;
	}

	lstp_uart_host_active = true;
	k_work_init_delayable(&lstp_uart_rx_drain_work, lstp_uart_rx_drain);
	uart_irq_callback_set(lstp_uart_dev, lstp_uart_irq_handler);
	uart_irq_rx_enable(lstp_uart_dev);
	return 0;
}

/*
 * With UDMA (dma = <1>), uart_poll_out() blocks only while the 1 KB TX ring
 * is full. This provides the backend's flow control:
 * the host driver does not reliably resend NAKed UART writes, so a buffered,
 * NAKing TX path loses whole chunks under load (seen on the EVB duplex test).
 */
int lstp_uart_tx_bytes(const uint8_t *data, size_t len)
{
	if (data == NULL || len == 0U) {
		return 0;
	}

	if (lstp_uart_dev == NULL) {
		return -ENODEV;
	}

	for (size_t i = 0; i < len; i++) {
		uart_poll_out(lstp_uart_dev, data[i]);
	}

	return 0;
}

void lstp_uart_backend_host_reset(void)
{
	/* ISR context: the ring is only touched under irq_lock elsewhere. */
	unsigned int key = irq_lock();

	atomic_add(&lstp_uart_rx_forward_dropped_bytes,
		   (atomic_val_t)ring_buf_size_get(&lstp_uart_rx_ring));
	ring_buf_reset(&lstp_uart_rx_ring);
	irq_unlock(key);
	atomic_set(&lstp_uart_rx_flush, 1);
}

void lstp_uart_resume_forwarding(void)
{
	/* The drain work only exists once lstp_uart_init() has succeeded. */
	if (lstp_uart_dev == NULL) {
		return;
	}

	k_work_reschedule(&lstp_uart_rx_drain_work, K_NO_WAIT);
}
