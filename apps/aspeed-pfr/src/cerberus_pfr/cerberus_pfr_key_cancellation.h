/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_CERBERUS_PFR)
#define KEY_CANCELLATION_MAX_KEY_ID 127

int verify_csk_key_id(struct pfr_manifest *manifest, uint32_t key_id);
int cancel_csk_key_id(struct pfr_manifest *manifest, uint32_t key_id);
#endif
