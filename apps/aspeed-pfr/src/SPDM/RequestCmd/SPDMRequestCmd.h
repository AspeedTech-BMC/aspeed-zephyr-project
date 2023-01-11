/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

int spdm_get_version(void *ctx);
int spdm_get_capabilities(void *ctx);
int spdm_negotiate_algorithms(void *ctx);
int spdm_get_digests(void *ctx);
int spdm_get_certificate(void *ctx, uint8_t slot_id);
int spdm_challenge(void *ctx, uint8_t slot_id, uint8_t measurements);
int spdm_get_measurements(void *ctx,
	uint8_t request_attribute, uint8_t measurement_operation,
	uint8_t *number_of_blocks,
	void* possible_measurements);
