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
 * LSTP UART backend driving the AST1040 hardware VUART0, which claims Host
 * eSPI port 0x3F8 with a bidirectional FIFO on SerIRQ 4. Selected by
 * CONFIG_OBMF_ESPI_UART_VUART; see lstp_uart_plain.c for the alternative.
 */

#include <zephyr/device.h>
#include <zephyr/drivers/clock_control.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/dt-bindings/clock/ast27xx_clock.h>
#include <zephyr/irq.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/sys/sys_io.h>
#include <zephyr/sys/util.h>

#include "lstp/lstp_backend.h"
#include "lstp_uart.h"
#include "lstp_uart_backend.h"

LOG_MODULE_DECLARE(lstp_uart, LOG_LEVEL_ERR);

#define VUART_RX_RING_BUF_SIZE 4096U

/* Use a preemptible RX workqueue below the LSTP task priority to avoid request starvation. */
#define VUART_RX_WORKQ_STACK_SIZE 2560
#define VUART_RX_WORKQ_PRIORITY   K_PRIO_PREEMPT(7)

#define VUART_RX_DRAIN_MAX_CHUNKS 8U

#define VUART_RX_CHUNK_SIZE 256U
#define VUART_RX_ISR_BUDGET 128U
#define VUART_RX_PAUSE_SPACE 512U

static const struct device *lstp_uart0_dev;
static uint8_t vuart_rx_buf[VUART_RX_RING_BUF_SIZE];
static atomic_t vuart_rx_paused;
static struct ring_buf vuart_rx_ringbuf;
static struct k_work_delayable vuart_rx_work;
/* Set on host reset so the worker discards a chunk peeked for the old host. */
static bool vuart_rx_flush;

/* Forwarding relies on ASPEED setup callbacks running in usbd_work_handler(). */
BUILD_ASSERT(IS_ENABLED(CONFIG_USB_ASPEED) && !IS_ENABLED(CONFIG_SMP),
	     "VUART RX reset serialization requires single-core ASPEED USB");

/*
 * USB event queue full: keep the chunk and retry, but only for a bounded
 * time. If the host never drains the IN endpoint, drop so a full ring does
 * not keep RX masked and stall the host's COM1 writes.
 */
#define VUART_RX_RETRY_DELAY K_MSEC(1)
#define VUART_RX_RETRY_MAX   50U
static unsigned int vuart_rx_retries;
/* Retries ran out: drop at once until a send succeeds, so COM1 is freed, not throttled. */
static bool vuart_rx_shedding;
static struct k_work_q vuart_rx_workq;
static K_THREAD_STACK_DEFINE(vuart_rx_workq_stack, VUART_RX_WORKQ_STACK_SIZE);

/* The VUART setup below programs vuart0 registers through this phandle. */
BUILD_ASSERT(DT_SAME_NODE(LSTP_UART_NODE, DT_NODELABEL(vuart0)),
	     "CONFIG_OBMF_ESPI_UART_VUART needs uart-controller = <&vuart0>");

#define VUART0_BASE_ADDR        DT_REG_ADDR(LSTP_UART_NODE)
#define VUART_GCRA_REG          (VUART0_BASE_ADDR + 0x20U)
#define VUART_GCRB_REG          (VUART0_BASE_ADDR + 0x24U)
#define VUART_ADDRL_REG         (VUART0_BASE_ADDR + 0x28U)
#define VUART_ADDRH_REG         (VUART0_BASE_ADDR + 0x2cU)

#define VUART_GCRA_DISABLE_HOST_TX_DISCARD BIT(5)
#define VUART_GCRA_VUART_EN                BIT(0)

#define LPC_BASE_ADDR           DT_REG_ADDR(DT_NODELABEL(lsc))
#define LPC_HICRB_REG           (LPC_BASE_ADDR + 0x100U)

/* Retain partial writes until the host drains RBR and THRE permits the remaining bytes. */
static uint8_t vuart_tx_pending[LSTP_MAX_PAYLOAD_SIZE];
static size_t vuart_tx_pending_len;
static size_t vuart_tx_pending_off;
static int64_t vuart_tx_pending_since;

/* Drop stalled TX tails before the host retry window expires (5 x 10 ms). */
#define VUART_TX_STALL_TIMEOUT_MS 30

/** Throw away a tail the host stopped taking. Caller holds irq_lock(). */
static void vuart_tx_drop_pending_locked(void)
{
	atomic_add(&lstp_uart_tx_dropped_bytes,
		   (uint32_t)(vuart_tx_pending_len - vuart_tx_pending_off));
	vuart_tx_pending_len = 0U;
	vuart_tx_pending_off = 0U;
	uart_irq_tx_disable(lstp_uart0_dev);
}

/** Push as much of the parked tail as THR will take. Caller holds irq_lock(). */
static void vuart_tx_flush_locked(void)
{
	while (vuart_tx_pending_off < vuart_tx_pending_len) {
		int filled = uart_fifo_fill(lstp_uart0_dev,
					    &vuart_tx_pending[vuart_tx_pending_off],
					    (int)(vuart_tx_pending_len -
						  vuart_tx_pending_off));

		if (filled <= 0) {
			return;
		}

		vuart_tx_pending_off += (size_t)filled;
		vuart_tx_pending_since = k_uptime_get();
	}

	vuart_tx_pending_len = 0U;
	vuart_tx_pending_off = 0U;

	/* Mask THRE when the tail is empty to prevent an interrupt storm. */
	uart_irq_tx_disable(lstp_uart0_dev);
}

int lstp_uart_tx_bytes(const uint8_t *data, size_t len)
{
	unsigned int key;
	size_t remaining;
	int filled;

	if (data == NULL || len == 0U) {
		return 0;
	}

	if (lstp_uart0_dev == NULL) {
		return -ENODEV;
	}

	key = irq_lock();

	/* NAK before accepting new bytes to preserve ordering and allow safe host retries. */
	if (vuart_tx_pending_len != 0U) {
		vuart_tx_flush_locked();

		if (vuart_tx_pending_len != 0U) {
			if ((k_uptime_get() - vuart_tx_pending_since) <
			    VUART_TX_STALL_TIMEOUT_MS) {
				irq_unlock(key);
				atomic_inc(&lstp_uart_tx_nak_events);
				return -EBUSY;
			}

			vuart_tx_drop_pending_locked();
		}
	}

	filled = uart_fifo_fill(lstp_uart0_dev, data, (int)len);
	if (filled < 0) {
		irq_unlock(key);
		atomic_inc(&lstp_uart_tx_nak_events);
		return -EBUSY;
	}

	remaining = len - (size_t)filled;
	if (remaining == 0U) {
		irq_unlock(key);
		return 0;
	}

	if (remaining > sizeof(vuart_tx_pending)) {
		/* Unreachable for LSTP payloads; never overrun the park. */
		atomic_add(&lstp_uart_tx_dropped_bytes, (uint32_t)remaining);
		irq_unlock(key);
		return -EMSGSIZE;
	}

	memcpy(vuart_tx_pending, data + filled, remaining);
	vuart_tx_pending_len = remaining;
	vuart_tx_pending_off = 0U;
	vuart_tx_pending_since = k_uptime_get();
	uart_irq_tx_enable(lstp_uart0_dev);
	irq_unlock(key);

	return 0;
}

static int lstp_uart_forward_rx_bytes(const uint8_t *data, size_t len)
{
	if (!lstp_uart_host_active || len == 0U) {
		return -EHOSTDOWN;
	}

	return lstp_uart_send_to_host(data, len);
}

static void vuart_rx_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	uint8_t chunk[VUART_RX_CHUNK_SIZE];
	uint32_t len;

	/* Bound each drain pass so continuous RX cannot monopolize the workqueue. */
	for (unsigned int i = 0; i < VUART_RX_DRAIN_MAX_CHUNKS; i++) {
		unsigned int key = irq_lock();

		if (vuart_rx_flush) {
			vuart_rx_flush = false;
			vuart_rx_retries = 0U;
			vuart_rx_shedding = false;
		}
		len = ring_buf_peek(&vuart_rx_ringbuf, chunk, sizeof(chunk));
		irq_unlock(key);
		if (len == 0U) {
			break;
		}

		/*
		 * Keep ASPEED USB reconfiguration (usbd_work_handler) from running
		 * between the flush check and enqueue. IRQs stay enabled: an ISR
		 * reset disables USB TX, and queued events carry the USB session.
		 */
		k_sched_lock();
		key = irq_lock();
		if (vuart_rx_flush) {
			/* Reset already counted the peeked bytes while clearing the ring. */
			irq_unlock(key);
			k_sched_unlock();
			continue;
		}
		irq_unlock(key);

		int ret = lstp_uart_forward_rx_bytes(chunk, len);

		key = irq_lock();
		if (vuart_rx_flush) {
			/* Reset cleared and counted this chunk; do not consume new RX. */
			irq_unlock(key);
			k_sched_unlock();
			continue;
		}

		bool full = ret == -ENOSPC || ret == -EBUSY;

		if (full && !vuart_rx_shedding) {
			if (vuart_rx_retries < VUART_RX_RETRY_MAX) {
				/* Transient: the bytes stay in the ring, as in the plain backend. */
				vuart_rx_retries++;
				irq_unlock(key);
				k_sched_unlock();
				k_work_schedule_for_queue(&vuart_rx_workq, &vuart_rx_work,
							  VUART_RX_RETRY_DELAY);
				return;
			}
			vuart_rx_shedding = true;
		}
		if (ret == 0) {
			vuart_rx_shedding = false;
		}
		vuart_rx_retries = 0U;
		(void)ring_buf_get(&vuart_rx_ringbuf, NULL, len);
		irq_unlock(key);
		k_sched_unlock();
		/* No host, or retries exhausted: drop rather than stall the host's COM1. */
		if (ret < 0 && ret != -EHOSTDOWN && ret != -EACCES) {
			atomic_add(&lstp_uart_rx_forward_dropped_bytes, len);
		}
	}

	/* Resume before requeueing: a masked RX stalls the host on COM1 writes. */
	if (atomic_cas(&vuart_rx_paused, 1, 0)) {
		uart_irq_rx_enable(lstp_uart0_dev);
	}

	if (!ring_buf_is_empty(&vuart_rx_ringbuf)) {
		k_work_schedule_for_queue(&vuart_rx_workq, &vuart_rx_work, K_NO_WAIT);
	}
}

static void lstp_uart0_irq_handler(const struct device *dev, void *user_data)
{
	ARG_UNUSED(user_data);

	if (!uart_irq_update(dev)) {
		return;
	}

	unsigned int budget = VUART_RX_ISR_BUDGET;

	while (budget != 0U && uart_irq_rx_ready(dev)) {
		uint8_t buf[16];
		int rd = uart_fifo_read(dev, buf, (int)MIN(sizeof(buf), budget));

		if (rd <= 0) {
			break;
		}
		budget -= (unsigned int)rd;

		uint32_t written = ring_buf_put(&vuart_rx_ringbuf, buf, (uint32_t)rd);
		if (written != (uint32_t)rd) {
			atomic_add(&lstp_uart_rx_dropped_bytes, (uint32_t)rd - written);
		}
	}

	/* Level-triggered: only masking RX lets the drain worker and everything
	 * below interrupt priority run again. Re-armed by vuart_rx_work_handler().
	 */
	if (ring_buf_space_get(&vuart_rx_ringbuf) < VUART_RX_PAUSE_SPACE) {
		uart_irq_rx_disable(dev);
		atomic_set(&vuart_rx_paused, 1);
	}

	/* Not uart_irq_tx_ready(): IIR reports RX first, so THRE never shows. */
	if (vuart_tx_pending_len != 0U) {
		unsigned int key = irq_lock();

		vuart_tx_flush_locked();
		irq_unlock(key);
	} else {
		uart_irq_tx_disable(dev);
	}

	if (uart_err_check(dev) & UART_ERROR_OVERRUN) {
		atomic_inc(&lstp_uart_rx_fifo_overruns);
	}

	k_work_schedule_for_queue(&vuart_rx_workq, &vuart_rx_work, K_NO_WAIT);
}

static void vuart0_hw_init(uint16_t port, uint8_t sirq)
{
	sys_write32(sys_read32(LPC_HICRB_REG) | BIT(18), LPC_HICRB_REG);

	sys_write32((uint32_t)(port & 0xFFU), VUART_ADDRL_REG);
	sys_write32((uint32_t)((port >> 8) & 0xFFU), VUART_ADDRH_REG);

	uint32_t gcrb = sys_read32(VUART_GCRB_REG) & ~0xF0U;
	gcrb |= ((uint32_t)sirq << 4) & 0xF0U;
	sys_write32(gcrb, VUART_GCRB_REG);

	uint32_t gcra = sys_read32(VUART_GCRA_REG);
	gcra |= VUART_GCRA_DISABLE_HOST_TX_DISCARD | VUART_GCRA_VUART_EN;
	sys_write32(gcra, VUART_GCRA_REG);
}

int lstp_uart_init(void)
{
	struct uart_config cfg = {
		.baudrate = 115200,
		.parity = UART_CFG_PARITY_NONE,
		.stop_bits = UART_CFG_STOP_BITS_1,
		.data_bits = UART_CFG_DATA_BITS_8,
		.flow_ctrl = UART_CFG_FLOW_CTRL_NONE,
	};

	const struct device *dev = DEVICE_DT_GET(LSTP_UART_NODE);

	/* Publish the device only once it is usable; TX/RX paths check for NULL. */
	if (!device_is_ready(dev)) {
		LOG_ERR("vuart0 device not ready");
		return -ENODEV;
	}

	ring_buf_init(&vuart_rx_ringbuf, sizeof(vuart_rx_buf), vuart_rx_buf);
	k_work_init_delayable(&vuart_rx_work, vuart_rx_work_handler);
	k_work_queue_start(&vuart_rx_workq, vuart_rx_workq_stack,
			   K_THREAD_STACK_SIZEOF(vuart_rx_workq_stack),
			   VUART_RX_WORKQ_PRIORITY, NULL);
	k_thread_name_set(&vuart_rx_workq.thread, "vuart_rx");

	/* 1. Explicitly enable UART0 clock gate in SCU (SCU1_CLK_GATE_UART0CLK = 11) */
	const struct device *clk_dev = DEVICE_DT_GET(DT_CLOCKS_CTLR(LSTP_UART_NODE));
	if (device_is_ready(clk_dev)) {
		clock_control_on(clk_dev, (clock_control_subsys_t)SCU1_CLK_GATE_UART0CLK);
	}

	vuart0_hw_init(0x3f8, 4);

	if (uart_configure(dev, &cfg) != 0) {
		LOG_ERR("failed to configure vuart0");
		return -EIO;
	}

	/* Override the driver's 8-byte RX trigger for short UEFI console writes. */
	sys_write32(0x07, VUART0_BASE_ADDR + 0x08);
	/* uart_aspeed_configure() leaves MCR untouched: assert DTR/RTS/OUT2. */
	sys_write32(0x0B, VUART0_BASE_ADDR + 0x10);

	lstp_uart0_dev = dev;
	lstp_uart_host_active = true;
	uart_irq_callback_set(dev, lstp_uart0_irq_handler);
	uart_irq_rx_enable(dev);
	LOG_INF("VUART0 Host 0x3F8 bridge initialized");
	return 0;
}

void lstp_uart_backend_host_reset(void)
{
	/* ISR context: discard COM1 output queued for the old USB host. */
	unsigned int key = irq_lock();

	atomic_add(&lstp_uart_rx_forward_dropped_bytes,
		   (atomic_val_t)ring_buf_size_get(&vuart_rx_ringbuf));
	ring_buf_reset(&vuart_rx_ringbuf);
	vuart_rx_flush = true;
	irq_unlock(key);
}

void lstp_uart_resume_forwarding(void)
{
	/* The RX work queue only runs once lstp_uart_init() has succeeded. */
	if (lstp_uart0_dev == NULL) {
		return;
	}

	k_work_schedule_for_queue(&vuart_rx_workq, &vuart_rx_work, K_NO_WAIT);
}
