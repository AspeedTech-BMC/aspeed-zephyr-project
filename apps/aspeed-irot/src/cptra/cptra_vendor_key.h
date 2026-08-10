/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2026 ASPEED Technology Inc.
 */

#ifndef CPTRA_VENDOR_KEY_H_
#define CPTRA_VENDOR_KEY_H_

/* Read OTP hash and compare against SHA384(vendor_key). */
int cptra_verify_vendor_key_hash(const uint8_t *vendor_key, uint32_t key_len);

/* Parse v1 image header to locate vendor key, then call
 * cptra_verify_vendor_key_hash().
 */
int cptra_validate_vendor_key_hash(const uint8_t *image_buf,
				    uint32_t image_size);

#endif
