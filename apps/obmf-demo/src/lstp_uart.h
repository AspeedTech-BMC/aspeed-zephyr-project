/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

#ifndef LSTP_UART_H
#define LSTP_UART_H

#include <stddef.h>
#include <stdint.h>

#include "lstp_common.h"

#define LSTP_UART_MIRROR_BUF_SIZE 256U

int lstp_uart_init(void);
void lstp_uart_set_host_active(bool active);
void shell_uart_mirror_tx_hook(const uint8_t *data, size_t len);
lstp_status_t lstp_uart_receive(uint8_t channel_id,
				struct lstp_hdr *hdr,
				uint8_t *payload, size_t payload_len,
				uint8_t *resp_payload, size_t *resp_payload_len);

#endif /* LSTP_UART_H */
