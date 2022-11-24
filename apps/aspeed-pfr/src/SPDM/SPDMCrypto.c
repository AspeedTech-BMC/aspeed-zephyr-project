/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMContext.h"

LOG_MODULE_REGISTER(spdm_crytpo, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_crypto_sign(void *ctx, uint8_t *input, size_t input_size, uint8_t *sig, size_t *sig_size)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	int ret;

	switch(context->remote.algorithms.base_asym_sel) {
	case SPDM_ALGORITHMS_BASE_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
	{
		mbedtls_mpi r, s;
		mbedtls_mpi_init(&r);
		mbedtls_mpi_init(&s);

		ret = mbedtls_ecdsa_sign(&context->key_pair.MBEDTLS_PRIVATE(grp),
				&r, &s, &context->key_pair.MBEDTLS_PRIVATE(d),
				input, input_size, context->random_callback, context);
		if (ret != 0) {
			LOG_HEXDUMP_ERR(input, input_size, "Hash:");
			LOG_ERR("mbedtls_ecdsa_sign ret=%x", -ret);
		}
		mbedtls_mpi_write_binary(&r, sig, 48);
		mbedtls_mpi_write_binary(&s, sig + 48, 48);
		*sig_size = 96;
		mbedtls_mpi_free(&s);
		mbedtls_mpi_free(&r);
		break;
	}
	default:
		LOG_ERR("Unsupported BaseAsymSel algorithm %08x", context->remote.algorithms.base_asym_sel);
		ret = -1;
		break;
	}

	return ret;
}

int spdm_crypto_verify(void *ctx, uint8_t slot_id, uint8_t *input, size_t input_size, uint8_t *sig, size_t sig_size)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	int ret;

	/* Get Public Key for verification */
	mbedtls_x509_crt *cur = &context->remote.certificate.certs[slot_id].chain;
	size_t cert_index = 0;
	while (cur) {
		++cert_index;
		if (cur->next != NULL)
			cur = cur->next;
		else {
			break;
		}
	}

	if (cur == NULL) {
		ret = -1;
		goto cleanup;
	}

	/* TODO: EC vs RSA */
	switch(mbedtls_pk_ec(cur->pk)->MBEDTLS_PRIVATE(grp).id) {
	case MBEDTLS_ECP_DP_SECP384R1:
	{
		mbedtls_mpi r, s;
		mbedtls_mpi_init(&r);
		mbedtls_mpi_init(&s);

		mbedtls_mpi_read_binary(&r, (uint8_t *)sig, 48);
		mbedtls_mpi_read_binary(&s, (uint8_t *)sig + 48, 48);

		ret = mbedtls_ecdsa_verify(
				&mbedtls_pk_ec(cur->pk)->MBEDTLS_PRIVATE(grp),
				input, input_size,
				&mbedtls_pk_ec(cur->pk)->MBEDTLS_PRIVATE(Q),
				&r, &s);
		if (ret != 0) {
			LOG_HEXDUMP_ERR(input, input_size, "Hash:");
			LOG_ERR("mbedtls_ecdsa_verify ret=%x", -ret);
		}
		mbedtls_mpi_free(&s);
		mbedtls_mpi_free(&r);
		break;
	}
	default:
		ret = -1;
		break;
	}

cleanup:
	return ret;
}
