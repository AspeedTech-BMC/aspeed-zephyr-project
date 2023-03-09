/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include "pfr/pfr_common.h"

#define MAX_CANCEL_KEY 8

int get_cancellation_policy_offset(uint32_t pc_type);
int verify_csk_key_id(struct pfr_manifest *manifest, uint8_t key_manifest_id, uint8_t key_id);
int cancel_csk_key_id(struct pfr_manifest *manifest, uint8_t key_manifest_id, uint8_t key_id);

