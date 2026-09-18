/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * P-384 verify on the Caliptra MCI ECDSA engine. MC_ECDSA384_SIG_VERIFY takes
 * a raw public key, a digest and (r, s), so it drops into pfr_util.c's backend
 * seam as-is. Own file: <zephyr/crypto/ecdsa.h> clashes with Cerberus's.
 */

#include <errno.h>

#include <zephyr/sys/util.h>

#include "pfr_ecdsa_cptra.h"

#if defined(CONFIG_CPTRA_MCI_ECDSA)

#include <zephyr/device.h>
#include <zephyr/crypto/crypto.h>
#include <zephyr/crypto/ecdsa.h>

#define CPTRA_ECDSA_P384_SCALAR_SIZE	48

int cptra_ecdsa_verify_middlelayer(const uint8_t *x, const uint8_t *y,
				   const uint8_t *digest, size_t length,
				   const uint8_t *r, const uint8_t *s)
{
	const struct device *dev = DEVICE_DT_GET_ANY(aspeed_cptra_mci_ecdsa);
	struct ecdsa_ctx ctx = { 0 };
	struct ecdsa_pkt pkt = { 0 };
	struct ecdsa_key key = { 0 };
	int ret;

	if (x == NULL || y == NULL || digest == NULL || r == NULL || s == NULL)
		return -EINVAL;

	/* The engine only does P-384 over a SHA-384-sized digest. */
	if (length != CPTRA_ECDSA_P384_SCALAR_SIZE)
		return -EINVAL;

	if (dev == NULL || !device_is_ready(dev))
		return -ENODEV;

	key.curve_id = ECC_CURVE_NIST_P384;
	key.qx = (char *)x;
	key.qy = (char *)y;

	ret = ecdsa_begin_session(dev, &ctx, &key);
	if (ret)
		return ret;

	/* pkt.m is the digest; the engine does no hashing of its own. */
	pkt.m = (uint8_t *)digest;
	pkt.m_len = (int)length;
	pkt.r = (uint8_t *)r;
	pkt.r_len = CPTRA_ECDSA_P384_SCALAR_SIZE;
	pkt.s = (uint8_t *)s;
	pkt.s_len = CPTRA_ECDSA_P384_SCALAR_SIZE;

	ret = ecdsa_verify(&ctx, &pkt);

	ecdsa_free_session(dev, &ctx);

	return ret;
}

#else /* !CONFIG_CPTRA_MCI_ECDSA */

int cptra_ecdsa_verify_middlelayer(const uint8_t *x, const uint8_t *y,
				   const uint8_t *digest, size_t length,
				   const uint8_t *r, const uint8_t *s)
{
	ARG_UNUSED(x);
	ARG_UNUSED(y);
	ARG_UNUSED(digest);
	ARG_UNUSED(length);
	ARG_UNUSED(r);
	ARG_UNUSED(s);

	return -ENOTSUP;
}

#endif /* CONFIG_CPTRA_MCI_ECDSA */
