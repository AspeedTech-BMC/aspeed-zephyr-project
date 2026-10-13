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
 * SHA-384 a flash region on the Caliptra SHA_ACC engine, double-buffered in
 * the IO SRAM so flash reads overlap hashing. 0 = digest in @hash_out;
 * negative = not done, caller falls back to the generic path.
 */
int pfr_sha_acc_hash_region(uint8_t device_id, uint32_t offset, uint32_t length,
			    uint8_t *hash_out, size_t hash_length);

/*
 * sram_buf has no allocator. Anything staging data there (test commands)
 * holds this lock so it cannot overwrite a verify in progress.
 */
void pfr_sha_acc_sram_lock(void);
void pfr_sha_acc_sram_unlock(void);

struct device;

/*
 * Test-only (flash_perf sha_acc): sequential read + SHA_ACC loop, no pipeline, over
 * a caller-chosen staging @buf so HyperRAM and IO SRAM can be compared. Read
 * and hash time are reported separately; the boot path does not use this.
 * @sha_acc_addr is the address handed to SHA_ACC for @buf, so alternative
 * bus mappings can be tried.
 */
int pfr_sha_acc_perf(const struct device *flash, uint32_t offset, uint32_t length,
		     uint8_t *buf, uintptr_t sha_acc_addr, uint32_t chunk_max,
		     uint8_t *hash_out,
		     uint32_t *read_ms, uint32_t *hash_ms);

/*
 * Test-only (flash_perf sha_acc ... pipe*): the pfr_sha_acc_hash_region()
 * pipeline over @nbuf (2..8) caller-chosen buffers, read with flash_read().
 * @read_ms/@hash_ms are per-side busy time; @total_ms is wall-clock.
 */
int pfr_sha_acc_perf_pipe(const struct device *flash, uint32_t offset, uint32_t length,
			  uint8_t *const buf[], const uintptr_t sha_acc_addr[], uint8_t nbuf,
			  uint32_t chunk_max, uint8_t *hash_out,
			  uint32_t *read_ms, uint32_t *hash_ms, uint32_t *total_ms);

#endif /* PFR_SHA_ACC_H_ */
