/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LSTP_UART_BACKEND_H
#define LSTP_UART_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/sys/atomic.h>

/*
 * Private interface between lstp_uart.c and the one UART backend CMakeLists.txt
 * links in: lstp_uart_shell.c when CONFIG_OBMF_LSTP_UART_SHELL is set,
 * lstp_uart_plain.c otherwise. Every backend also defines the lstp_uart_tx_bytes() declared in
 * lstp_uart.h.
 */

/* Owned by lstp_uart.c, read by the backend RX path. */
extern bool lstp_uart_host_active;

/* Owned by lstp_uart.c, accumulated by the backend, reported by lstp_uart_get_stats(). */
extern atomic_t lstp_uart_rx_dropped_bytes;         /* RX ring buffer overflow */
extern atomic_t lstp_uart_rx_fifo_overruns;         /* LSR.OE events, not lost bytes */
extern atomic_t lstp_uart_tx_dropped_bytes;
extern atomic_t lstp_uart_tx_nak_events;
extern atomic_t lstp_uart_rx_forward_dropped_bytes; /* drained but rejected downstream */

/* Bring up the host UART. Called once as the UART channel's init hook. */
int lstp_uart_init(void);

/* Kick the backend's RX drain after the host comes back. */
void lstp_uart_resume_forwarding(void);

/* ISR context: the host went away; drop RX buffered for it. */
void lstp_uart_backend_host_reset(void);

#endif /* LSTP_UART_BACKEND_H */
