/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <zephyr/kernel.h>
#include "ecdsa_aspeed.h"
#include <zephyr/crypto/ecdsa_structs.h>
#include <zephyr/crypto/ecdsa.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ecdsa_middle_aspeed, CONFIG_LOG_DEFAULT_LEVEL);

#define ECDSA_P384_SCALAR_SIZE 48

static const struct device *ecdsa_verify_device(void)
{
#if defined(CONFIG_PFR_ECDSA_P384_BACKEND_CPTRA)
	return DEVICE_DT_GET_ANY(aspeed_cptra_mci_ecdsa);
#elif defined(CONFIG_ECDSA_ASPEED)
	return DEVICE_DT_GET_ANY(aspeed_ecdsa);
#else
	return NULL;
#endif
}

/**
 * Verify a P-384 signature over an already computed SHA-384 digest through
 * the selected Zephyr ECDSA device (ASPEED or Caliptra MCI).
 *
 * @param public_key_x : Q(x) public key
 * @param public_key_y : Q(y) public key
 * @param digest : hash data
 * @param length : digest length
 * @param signature_r : signature r
 * @param signature_s : signature s
 *
 * @return 0 if the digest matches the signature or an error code.
 *
 */
int aspeed_ecdsa_verify_middlelayer(uint8_t *public_key_x, uint8_t *public_key_y,
	const uint8_t *digest, size_t length, uint8_t *signature_r, uint8_t *signature_s)
{
	const struct device *dev = ecdsa_verify_device();
	struct ecdsa_ctx ini = { 0 };
	struct ecdsa_pkt pkt = { 0 };
	struct ecdsa_key ek = { 0 };
	int status;

	if (public_key_x == NULL || public_key_y == NULL || digest == NULL ||
	    signature_r == NULL || signature_s == NULL || length != ECDSA_P384_SCALAR_SIZE) {
		return -EINVAL;
	}

	if (dev == NULL || !device_is_ready(dev)) {
		LOG_ERR("ECDSA device not ready");
		return -ENODEV;
	}

	ek.curve_id = ECC_CURVE_NIST_P384;
	ek.qx = public_key_x;
	ek.qy = public_key_y;
	pkt.m = (uint8_t *) digest;
	pkt.r = signature_r;
	pkt.s = signature_s;
	pkt.m_len = length;
	pkt.r_len = length;
	pkt.s_len = length;

	status = ecdsa_begin_session(dev, &ini, &ek);
	if (status) {
		LOG_ERR("begin session failed: %d", status);
		return status;
	}

	status = ecdsa_verify(&ini, &pkt);
	ecdsa_free_session(dev, &ini);
	return status;
}

