/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

#ifndef LSTP_SPI_H
#define LSTP_SPI_H

#include <stdint.h>
#include <stddef.h>
#include "lstp_common.h"

/**
 * @brief Populate the cached SFDP data used by the SPI flash wrapper.
 *
 * Reads a bounded SFDP window from the CS0 flash device at startup so
 * runtime LSTP SFDP requests can be served from RAM.
 *
 * @return 0 on success, negative errno-style value on failure
 */
int lstp_spi_init(void);

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
 * @param send_response Set to true when the caller should emit a solicited
 *                      response packet, false for side-effect-only commands
 * @return LSTP status code
 */
lstp_status_t lstp_spi_receive(uint8_t channel_id,
				struct lstp_hdr *hdr,
				uint8_t *payload, size_t payload_len,
				uint8_t *resp_payload, size_t *resp_payload_len,
				bool *send_response);

#endif /* LSTP_SPI_H */
