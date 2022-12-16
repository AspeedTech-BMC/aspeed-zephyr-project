/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_INTEL_PFR)
#define KEY_CANCELLATION_MAX_KEY_ID 127
// Key cancellation certificate and decommission capsule shares the same size
#define KCH_CAN_CERT_OR_DECOMM_CAP_PC_SIZE 128
#define KCH_CAN_CERT_RESERVED_SIZE 124
#define DECOMM_CAP_RESERVED_SIZE 128

int get_cancellation_policy_offset(uint32_t pc_type);
int validate_key_cancellation_flag(struct pfr_manifest *manifest);
int verify_csk_key_id(struct pfr_manifest *manifest, uint8_t key_id);
int cancel_csk_key_id(struct pfr_manifest *manifest, uint8_t key_id);
#endif
