/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 * SPDX-License-Identifier: MIT
 */

/*
 * libspdm random number source backed by the Zephyr CSPRNG (on AST2700, the
 * hardware TRNG). SPDM nonces and ECDHE keys depend on it, so there is no
 * fallback to a non-cryptographic PRNG: a CSPRNG failure is reported as such.
 *
 * - NULL cryptlib: its libspdm_random_bytes() reports success without writing
 *   the buffer (all-zero nonces), so it is replaced by the one below.
 * - mbedTLS cryptlib: its rand.c builds libspdm_random_bytes() and the mbedTLS
 *   RNG callback on top of libspdm_get_random_number_64(), provided here.
 */

#include <zephyr/random/random.h>

#include "hal/base.h"

#if !defined(CONFIG_CSPRNG_ENABLED)
#error "libspdm needs a cryptographically secure RNG (CONFIG_CSPRNG_ENABLED)"
#endif

#if defined(CONFIG_DMTF_LIBSPDM_OS_STUB_CRYPTLIB_MBEDTLS)
bool libspdm_get_random_number_64(uint64_t *rand_data)
{
	if (rand_data == NULL)
		return false;

	return sys_csrand_get(rand_data, sizeof(*rand_data)) == 0;
}
#else
bool libspdm_random_bytes(uint8_t *output, size_t size)
{
	if (output == NULL)
		return false;

	if (size == 0)
		return true;

	return sys_csrand_get(output, size) == 0;
}
#endif
