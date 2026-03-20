/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LSTP_USB_H
#define LSTP_USB_H

#include <stdint.h>
#include <stddef.h>

/* USB Endpoint Addresses (Standard Bulk Config) */
#define LSTP_IN_EP_ADDR  0x81
#define LSTP_OUT_EP_ADDR 0x01

/* LSTP USB Buffer max size (Must be 512 for High-Speed USB Bulk Endpoints) */
#define LSTP_USB_MAX_EP_BUFFER_SIZE 512

/**
 * @brief Initialize the USB transport layer for LSTP.
 *
 * @return 0 on success, negative errno on failure.
 */
int lstp_usb_init(void);

/**
 * @brief Send LSTP response back over USB Bulk IN endpoint.
 *
 * @param data Buffer containing LSTP message.
 * @param len  Length of the message in bytes.
 *
 * @return 0 on success, negative errno on failure.
 */
int lstp_usb_send(const uint8_t *data, size_t len);

#endif /* LSTP_USB_H */
