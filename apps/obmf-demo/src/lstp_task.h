/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LSTP_TASK_H
#define LSTP_TASK_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Initialize the LSTP Background Task.
 *
 * Spawns the Zephyr thread and initializes the message queues used for
 * background processing of hardware commands.
 */
void lstp_task_init(void);

/**
 * @brief Submit a GPIO LSTP request to the background task.
 *
 * Called from the USB Rx ISR context (via lstp_router_receive). The packet is
 * copied into the task queue and processing happens asynchronously. The
 * response is sent via lstp_usb_send() from the task thread.
 *
 * @param buffer Raw buffer containing the request header + payload
 * @param len    Length of the packet
 * @return 0 if queued successfully, negative error code otherwise.
 */
int lstp_task_submit_req(uint8_t *buffer, size_t len);

/**
 * @brief Submit a GPIO IRQ event to the background task (ISR-safe).
 *
 * Called from a GPIO interrupt callback. Reads the current pin value,
 * enqueues an IRQ event, and wakes the task thread.
 *
 * @param gpio_index Logical LSTP GPIO index that fired the interrupt
 */
void lstp_task_submit_gpio_irq(uint16_t gpio_index);

#endif /* LSTP_TASK_H */
