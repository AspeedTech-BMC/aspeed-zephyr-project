/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PFR_ECDSA_CPTRA_H_
#define PFR_ECDSA_CPTRA_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Verify a P-384 signature over a SHA-384 digest on the Caliptra MCI ECDSA
 * engine. @x/@y/@r/@s are 48 bytes each. 0 = valid, negative = not verified.
 */
int cptra_ecdsa_verify_middlelayer(const uint8_t *x, const uint8_t *y,
				   const uint8_t *digest, size_t length,
				   const uint8_t *r, const uint8_t *s);

#endif /* PFR_ECDSA_CPTRA_H_ */
