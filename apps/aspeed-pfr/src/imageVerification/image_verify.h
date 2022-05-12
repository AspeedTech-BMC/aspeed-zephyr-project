/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ZEPHYR_ASPEED_PFR_SRC_IMAGEVERIFICATION_IMAGE_VERIFY_H_
#define ZEPHYR_ASPEED_PFR_SRC_IMAGEVERIFICATION_IMAGE_VERIFY_H_

#include <zephyr.h>
#include <crypto/signature_verification_rsa_wrapper.h>
#include <crypto/rsa.h>
#include <include/definitions.h>
void handleVerifyEntryState(/* TBD */);
void handleVerifyExitState(/* TBD */);

int perform_image_verification();
int signature_verification_init(struct signature_verification *verification);
int read_rsa_public_key(struct rsa_public_key *public_key);
#endif /* ZEPHYR_ASPEED_PFR_SRC_IMAGEVERIFICATION_IMAGE_VERIFY_H_ */
