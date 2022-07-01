/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

int aspeed_ecdsa_verify_middlelayer(uint8_t *public_key_x, uint8_t *public_key_y,
	const uint8_t *digest, size_t length, uint8_t *signature_r, uint8_t *signature_s);
