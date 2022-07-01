/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <zephyr.h>
#include <crypto/signature_verification_rsa_wrapper.h>
#include <crypto/rsa.h>
#include <include/definitions.h>
void handleVerifyEntryState(/* TBD */);
void handleVerifyExitState(/* TBD */);

int perform_image_verification(void);
int signature_verification_init(struct signature_verification *verification);
int read_rsa_public_key(struct rsa_public_key *public_key);

