/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

int spdm_crypto_sign(void *ctx, uint8_t *input, size_t input_size, uint8_t *sig, size_t *sig_size,
		bool sig_context_hash, uint8_t *sig_context, size_t sig_context_len);
int spdm_crypto_verify(void *ctx, uint8_t slot_id, uint8_t *input, size_t input_size, uint8_t *sig, size_t sig_size,
		bool sig_context_hash, uint8_t *sig_context, size_t sig_context_len);

