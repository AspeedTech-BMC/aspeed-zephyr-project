/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PFR_SHA_ACC_H_
#define PFR_SHA_ACC_H_

#include <stddef.h>
#include <stdint.h>

/*
 * SHA-384 a flash region on the Caliptra SHA_ACC engine. 0 = digest in
 * @hash_out; negative = not done, caller falls back to the generic path.
 */
int pfr_sha_acc_hash_region(uint8_t device_id, uint32_t offset, uint32_t length,
			    uint8_t *hash_out, size_t hash_length);

#endif /* PFR_SHA_ACC_H_ */
