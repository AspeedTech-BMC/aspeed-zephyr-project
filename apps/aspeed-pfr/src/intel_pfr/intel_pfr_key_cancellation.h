/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#define KEY_CANCELLATION_MAX_KEY_ID 127

int validate_key_cancellation_flag(struct pfr_manifest *manifest);
int verify_csk_key_id(struct pfr_manifest *manifest, uint32_t key_id);
int cancel_csk_key_id(struct pfr_manifest *manifest, uint32_t key_id);

