/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

int decrypt_aspeed(const struct rsa_key *key, const uint8_t *encrypted, size_t in_length, uint8_t *decrypted, size_t out_length);
int sig_verify_aspeed(const struct rsa_key *key, const uint8_t *signature, int sig_length, const uint8_t *match, size_t match_length);
