/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

#ifndef LSTP_ROUTER_H
#define LSTP_ROUTER_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Initialize the LSTP router subsystem and its internal channel state.
 */
void lstp_router_init(void);

/**
 * @brief Receive an LSTP packet from a transport layer (e.g. USB) and route it.
 *
 * If the packet is a valid request, it resolves the channel and processes it.
 * Responses are generated and sent back via lstp_usb_send().
 *
 * @param buffer Raw buffer containing the request
 * @param len    Length of the packet
 */
void lstp_router_receive(uint8_t *buffer, size_t len);

/**
 * @brief Send an unsolicited GPIO IRQ event packet to the host.
 *
 * Called from lstp_task's process_gpio_irq. Builds and transmits an IrqEvent
 * packet (lstp_hdr + lstp_gpio_irq_event_request) on the GPIO channel.
 * Mirrors LstpRouter::send_gpio_irq_event in OpenSMA.
 *
 * @param gpio_index Logical LSTP GPIO index that fired the interrupt
 * @param value      Current GPIO state (lstp_gpio_state_t)
 */
void lstp_router_send_gpio_irq_event(uint16_t gpio_index, uint8_t value);

/**
 * @brief Send UART RX bytes to the host on the LSTP UART channel.
 *
 * @param data UART payload bytes
 * @param len  Number of bytes in @p data
 * @return 0 on success, negative errno-style value on transport failure
 */
int lstp_router_send_uart_data(const uint8_t *data, size_t len);

#endif /* LSTP_ROUTER_H */
