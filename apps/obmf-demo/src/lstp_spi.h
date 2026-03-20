/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LSTP_SPI_H
#define LSTP_SPI_H

#include <stdint.h>
#include <stddef.h>
#include "lstp_common.h"

/**
 * @brief Handle an incoming LSTP SPI channel request.
 *
 * Executes the SPI transfer synchronously (Config/Read/Write/WriteRead/PostedWrite)
 * and fills the response payload. Mirrors OpenSMA's LstpRouter::receive_spi and
 * Flashrom::handle_tx.
 *
 * @param channel_id  LSTP channel ID (used to select the SPI bus if multiple)
 * @param hdr         Pointer to the request LSTP header
 * @param payload     Pointer to the request payload (after header)
 * @param payload_len Length of the request payload in bytes
 * @param resp_payload Output buffer for the response payload (after header)
 * @param resp_payload_len Set to the number of bytes written to resp_payload
 * @return LSTP status code
 */
lstp_status_t lstp_spi_receive(uint8_t channel_id,
				struct lstp_hdr *hdr,
				uint8_t *payload, size_t payload_len,
				uint8_t *resp_payload, size_t *resp_payload_len);

#endif /* LSTP_SPI_H */
