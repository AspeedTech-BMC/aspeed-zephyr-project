/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

int handle_spdm_mctp_message(uint8_t bus, uint8_t src_eid, void *buffer, size_t *length);
