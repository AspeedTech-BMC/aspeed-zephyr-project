/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 * SPDX-License-Identifier: MIT
 */

/*
 * ECDSA signing for libspdm with the responder key held by Caliptra.
 *
 * Every other EC operation (ECDHE for KEY_EXCHANGE, signature verification,
 * key contexts) comes from libspdm's mbedTLS cryptlib. Its signer is built as
 * libspdm_ecdsa_sign_mbedtls() (CONFIG_DMTF_LIBSPDM_APP_ECDSA_SIGN), so this
 * file only decides which key signs:
 *   - ec_context == &irot_caliptra_identity_key: the responder identity key,
 *     which never leaves Caliptra; libspdm_responder_data_sign() passes it.
 *   - NULL: rejected, so a caller whose key load failed cannot end up
 *     signing with the device identity key.
 *   - anything else: a software key libspdm loaded itself; sign with mbedTLS.
 */

#include "internal_crypt_lib.h"
#include "spdm/irot_ec.h"

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/cptra.h>
#include <zephyr/drivers/misc/aspeed/cptra_ipc.h>
#include <cptra/cptra_api.h>

LOG_MODULE_DECLARE(spdm_secret);

#if !defined(CONFIG_DMTF_LIBSPDM_APP_ECDSA_SIGN)
#error "ec.c replaces libspdm_ecdsa_sign(); enable CONFIG_DMTF_LIBSPDM_APP_ECDSA_SIGN"
#endif

#define CPTRA_P384_DIGEST_SIZE	48
#define CPTRA_P384_SIG_SIZE	96

bool libspdm_ecdsa_sign_mbedtls(void *ec_context, size_t hash_nid,
				const uint8_t *message_hash, size_t hash_size,
				uint8_t *signature, size_t *sig_size);

/* The renamed mbedTLS signer must keep libspdm_ecdsa_sign()'s signature */
BUILD_ASSERT(__builtin_types_compatible_p(__typeof__(libspdm_ecdsa_sign_mbedtls),
					  __typeof__(libspdm_ecdsa_sign)),
	     "libspdm_ecdsa_sign_mbedtls() no longer matches libspdm_ecdsa_sign()");

char irot_caliptra_identity_key;

static bool cptra_ecdsa_sign(const uint8_t *message_hash, size_t hash_size,
			     uint8_t *signature, size_t *sig_size)
{
	struct cptra_invoke_dpe_command_ia input;
	struct cptra_invoke_dpe_command_oa output;
	struct dpe_sign_i *sign_input = NULL;
	struct dpe_sign_o *sign_output = NULL;
	int ret;
	size_t sign_len = 96;
	size_t digest_len = 48;

	memset(&input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(&output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	sign_input = (struct dpe_sign_i *)input.data;
	sign_output = (struct dpe_sign_o *)output.data;

	input.data_size = sizeof(struct dpe_sign_i);
	sign_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	sign_input->cmd_hdr.cmd = SIGN;
	sign_input->cmd_hdr.profile = P384Sha384; // TODO: 384 vs 256

		// Input message is a digest
	memcpy(sign_input->digest, message_hash, hash_size);

	LOG_HEXDUMP_DBG(sign_input->digest, digest_len, "digest to sign:");

	ret = cptra_api_transfer(CPTRA_IPCCMD_INVOKE_DPE_COMMAND,
				 (uint8_t *)&input, sizeof(struct cptra_invoke_dpe_command_ia),
				 CPTRA_IPC_RX_TYPE_EXTERNAL,
				 (uint8_t *)&output, sizeof(struct cptra_invoke_dpe_command_oa));

	LOG_HEXDUMP_DBG(&output, 32, "DPE Cmd Output:");

	if (ret) {
		LOG_ERR("Failed to send command to caliptra");
		return false;
	} else if (output.fips_status != 0) {
		LOG_ERR("FIPS error from caliptra");
		return false;
	}

	LOG_HEXDUMP_DBG(sign_output->signature_r, sign_len / 2, "signature_r:");
	LOG_HEXDUMP_DBG(sign_output->signature_s, sign_len / 2, "signature_s:");

	memcpy(signature, sign_output->signature_r, sign_len / 2);
	memcpy(signature + sign_len / 2, sign_output->signature_s, sign_len / 2);

	LOG_HEXDUMP_DBG(signature, sign_len, "signature (r||s):");

	return true;
}

bool libspdm_ecdsa_sign(void *ec_context, size_t hash_nid,
			const uint8_t *message_hash, size_t hash_size,
			uint8_t *signature, size_t *sig_size)
{
	if (ec_context == NULL) {
		LOG_ERR("ECDSA sign without a key context");
		return false;
	}

	if (ec_context != &irot_caliptra_identity_key)
		return libspdm_ecdsa_sign_mbedtls(ec_context, hash_nid, message_hash, hash_size,
						  signature, sig_size);

	/* Caliptra DPE signs with its P-384 key over a SHA-384 digest only */
	if (hash_nid != LIBSPDM_CRYPTO_NID_SHA384 || hash_size != CPTRA_P384_DIGEST_SIZE ||
	    message_hash == NULL || sig_size == NULL) {
		LOG_ERR("Caliptra signing needs a SHA-384 digest (nid %zu, size %zu)",
			hash_nid, hash_size);
		return false;
	}

	if (signature == NULL || *sig_size < CPTRA_P384_SIG_SIZE) {
		*sig_size = CPTRA_P384_SIG_SIZE;
		return false;
	}

	if (!cptra_ecdsa_sign(message_hash, hash_size, signature, sig_size))
		return false;

	*sig_size = CPTRA_P384_SIG_SIZE;
	return true;
}
