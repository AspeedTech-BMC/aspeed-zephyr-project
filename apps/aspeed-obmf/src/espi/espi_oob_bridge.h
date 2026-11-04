/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ESPI_OOB_BRIDGE_H
#define ESPI_OOB_BRIDGE_H

#include <stddef.h>
#include <stdint.h>
#include <zephyr/device.h>
#include <zephyr/sys/util.h>

#include "espi_bridge.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ESPI_OOB_RX_STATUS_OFFSET  (ESPI_MIRROR_BASE + 0x0100U)
#define ESPI_OOB_RX_TAG_OFFSET     (ESPI_MIRROR_BASE + 0x0101U)
#define ESPI_OOB_RX_LEN_OFFSET     (ESPI_MIRROR_BASE + 0x0102U)
#define ESPI_OOB_RX_DATA_OFFSET    (ESPI_MIRROR_BASE + 0x0104U)
#define ESPI_OOB_RX_DATA_SIZE      124U

#define ESPI_OOB_TX_CTRL_OFFSET    (ESPI_MIRROR_BASE + 0x0180U)
#define ESPI_OOB_TX_TAG_OFFSET     (ESPI_MIRROR_BASE + 0x0181U)
#define ESPI_OOB_TX_LEN_OFFSET     (ESPI_MIRROR_BASE + 0x0182U)
#define ESPI_OOB_TX_DATA_OFFSET    (ESPI_MIRROR_BASE + 0x0184U)
#define ESPI_OOB_TX_DATA_SIZE      108U

#define ESPI_OOB_RX_PKT_CNT_OFFSET (ESPI_MIRROR_BASE + 0x01f0U)
#define ESPI_OOB_TX_PKT_CNT_OFFSET (ESPI_MIRROR_BASE + 0x01f4U)
#define ESPI_OOB_MAILBOX_END       (ESPI_MIRROR_BASE + 0x01f8U)

#define ESPI_OOB_STATUS_READY      BIT(0)
#define ESPI_OOB_STATUS_OVERRUN    BIT(1)

#define ESPI_OOB_CTRL_TRIGGER      BIT(0)
#define ESPI_OOB_CTRL_BUSY         BIT(1)
#define ESPI_OOB_CTRL_ECHO_EN      BIT(2)

int espi_oob_bridge_init(const struct device *dev);

void espi_oob_bridge_service(void);

/* RX status is W1C; RX data/counters are read-only. Firmware owns TX BUSY. */
int espi_oob_bridge_mmio_write(uint32_t offset, const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ESPI_OOB_BRIDGE_H */
