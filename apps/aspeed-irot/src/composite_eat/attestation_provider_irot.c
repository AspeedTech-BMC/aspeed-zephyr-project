/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <stdlib.h>
#include <mbedtls/sha512.h>

#include <cptra/cptra_api.h>
#include <zephyr/drivers/cptra.h>
#include <zephyr/drivers/misc/aspeed/cptra_ipc.h>
#include <zephyr/logging/log.h>

#include <composite_eat/generation_request.h>
#include <composite_eat/types.h>
#include <software_platform.h>
#include <mctp_vdm_pci.h>

#include "attestation_provider_irot.h"
#include "evidence_provider_irot.h"
#include "platform_attestation.h"

LOG_MODULE_REGISTER(composite_eat);

int begin_identity(void *context, void **identity_handle,
                          struct composite_eat_attestation_identity *identity) {
	void *cert_data = NULL;
	uint32_t cert_length = 0;
	int result;
	
	identity->certificate_count = 0;
	identity->certificates = 
		(struct composite_eat_der_certificate *)malloc(
			COMPOSITE_EAT_MAX_CERTIFICATES * sizeof(struct composite_eat_der_certificate)
		);

	result = cptra_get_cached_certificate(CPTRA_CACHED_DPE_LEAF_CERT, &cert_data, &cert_length);
	if (result == 0) {
		struct composite_eat_der_certificate cert_der = {cert_data, cert_length};
		memcpy(&identity->certificates[identity->certificate_count], &cert_der,
			sizeof(struct composite_eat_der_certificate));
		identity->certificate_count++;
	}

	result = cptra_get_cached_certificate(CPTRA_CACHED_RT_ALIAS_CERT, &cert_data, &cert_length);
	if (result == 0) {
		struct composite_eat_der_certificate cert_der = {cert_data, cert_length};
		memcpy(&identity->certificates[identity->certificate_count], &cert_der,
			sizeof(struct composite_eat_der_certificate));
		identity->certificate_count++;
	}

	result = cptra_get_cached_certificate(CPTRA_CACHED_FMC_ALIAS_CERT, &cert_data, &cert_length);
	if (result == 0) {
		struct composite_eat_der_certificate cert_der = {cert_data, cert_length};
		memcpy(&identity->certificates[identity->certificate_count], &cert_der,
			sizeof(struct composite_eat_der_certificate));
		identity->certificate_count++;
	}

	result = cptra_get_cached_certificate(CPTRA_CACHED_LDEVID_CERT, &cert_data, &cert_length);
	if (result == 0) {
		struct composite_eat_der_certificate cert_der = {cert_data, cert_length};
		memcpy(&identity->certificates[identity->certificate_count], &cert_der,
			sizeof(struct composite_eat_der_certificate));
		identity->certificate_count++;
	}
	
	result = cptra_get_cached_certificate(CPTRA_CACHED_IDEVID_CERT, &cert_data, &cert_length);
	if (result == 0) {
		struct composite_eat_der_certificate cert_der = {cert_data, cert_length};
		memcpy(&identity->certificates[identity->certificate_count], &cert_der,
			sizeof(struct composite_eat_der_certificate));
		identity->certificate_count++;
	}

	result = cptra_get_cached_certificate(CPTRA_CACHED_ASPEED_SUB_CA_CERT, &cert_data, &cert_length);
	if (result == 0) {
		struct composite_eat_der_certificate cert_der = {cert_data, cert_length};
		memcpy(&identity->certificates[identity->certificate_count], &cert_der,
			sizeof(struct composite_eat_der_certificate));
		identity->certificate_count++;
	}

	result = cptra_get_cached_certificate(CPTRA_CACHED_ASPEED_ROOT_CA_CERT, &cert_data, &cert_length);
	if (result == 0) {
		struct composite_eat_der_certificate cert_der = {cert_data, cert_length};
		memcpy(&identity->certificates[identity->certificate_count], &cert_der,
			sizeof(struct composite_eat_der_certificate));
		identity->certificate_count++;
	}

	*identity_handle = identity;

	return 0;
}

void end_identity(void *context, void *identity_handle) {
	struct composite_eat_attestation_identity *identity = identity_handle;
	
	for (int i = 0; i < identity->certificate_count; ++i) {
		free(identity->certificates[i].data);
	}

	free(identity->certificates);

}

int hash_start_sha384(void *context, void **hash_handle) {
	int ret;
	mbedtls_sha512_context *ctx = NULL;

	ctx = (mbedtls_sha512_context *)malloc(sizeof(mbedtls_sha512_context));
	if (!ctx) {
		return -1;
	}

	mbedtls_sha512_init(ctx);
	ret = mbedtls_sha512_starts(ctx, 1);

	*hash_handle = ctx;

	return ret;
}

int hash_update(void *context, void *hash_handle, const uint8_t *data, size_t length) {
	int ret;
	mbedtls_sha512_context *ctx = (mbedtls_sha512_context *)hash_handle;
	
	ret = mbedtls_sha512_update(ctx, data, length);

	return ret;
}

int hash_finish(void *context, void *hash_handle,
                       uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH]) {
	int ret;
	mbedtls_sha512_context *ctx = (mbedtls_sha512_context *)hash_handle;

	ret = mbedtls_sha512_finish(ctx, digest);

	mbedtls_sha512_free(ctx);
	free(ctx);

	return ret;
}

void hash_abort(void *context, void *hash_handle) {
	mbedtls_sha512_context *ctx = (mbedtls_sha512_context *)hash_handle;
	mbedtls_sha512_free(ctx);
	free(ctx);
}

int sign_es384_digest(void *context, void *identity_handle,
                             const uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH],
                             uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH]) {
	struct cptra_invoke_dpe_command_ia *input =
		(struct cptra_invoke_dpe_command_ia *)malloc(sizeof(struct cptra_invoke_dpe_command_ia));
	struct cptra_invoke_dpe_command_oa *output =
		(struct cptra_invoke_dpe_command_oa *)malloc(sizeof(struct cptra_invoke_dpe_command_oa));
	struct dpe_sign_i *sign_input = NULL;
	struct dpe_sign_o *sign_output = NULL;
	int ret = 0;
	size_t sign_len = COMPOSITE_EAT_ES384_SIGNATURE_LENGTH;

	memset(input, 0, sizeof(struct cptra_invoke_dpe_command_ia));
	memset(output, 0, sizeof(struct cptra_invoke_dpe_command_oa));

	sign_input = (struct dpe_sign_i *)input->data;
	sign_output = (struct dpe_sign_o *)output->data;

	input->data_size = sizeof(struct dpe_sign_i);
	sign_input->cmd_hdr.magic = DPE_COMMAND_MAGIC;
	sign_input->cmd_hdr.cmd = SIGN;
	sign_input->cmd_hdr.profile = P384Sha384; // TODO: 384 vs 256

		// Input message is a digest
	memcpy(sign_input->digest, digest, COMPOSITE_EAT_SHA384_LENGTH);

	LOG_HEXDUMP_INF(sign_input->digest, 48, "Signing digest:");

	ret = cptra_ipc_transfer(CPTRA_IPCCMD_INVOKE_DPE_COMMAND,
				 (uint8_t *)input, sizeof(struct cptra_invoke_dpe_command_ia),
				 CPTRA_IPC_RX_TYPE_EXTERNAL,
				 (uint8_t *)output, sizeof(struct cptra_invoke_dpe_command_oa));

	// LOG_HEXDUMP_DBG(&output, 32, "DPE Cmd Output:");
	LOG_HEXDUMP_INF(sign_output->signature_r, 48, "signature_r:");
	LOG_HEXDUMP_INF(sign_output->signature_s, 48, "signature_s:");

	if (ret) {
		LOG_ERR("Failed to send command to caliptra");
		ret = -1;
		goto cleanup;
	} else if (output->fips_status != 0) {
		LOG_ERR("FIPS error from caliptra");
		ret = -1;
		goto cleanup;
	}

	memcpy(signature, sign_output->signature_r, sign_len / 2);
	memcpy(signature + sign_len / 2, sign_output->signature_s, sign_len / 2);

cleanup:
	if (input)
		free(input);
	if (output)
		free(output);

	return ret;
}

uint8_t mctp_vdm_pci_generate_eat_handle(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_params ext_params)
{
	struct mctp_vdm_pci_req *req = (struct mctp_vdm_pci_req *)buf;
	uint8_t *resp_buf = (uint8_t *)malloc(COMPOSITE_EAT_MAX_RESPONSE_LENGTH);
	int result;

	static const uint8_t ueid[] = {1, 1, 1, 1, 1, 1, 1};
	static const uint8_t profile[] = "https://example.invalid/profile";
	static const uint8_t evidence_bytes[] = {0xa0};
	static const uint8_t certificate_bytes[] = {0x30, 0x00};
	struct composite_eat_generation_request request = {0};
	struct composite_eat_local_evidence local_evidence = {
		.content_format = 60u,
		.encoded = {evidence_bytes, sizeof(evidence_bytes)},
	};
	struct composite_eat_evidence_snapshot evidence = {
		.ueid = {ueid, sizeof(ueid)},
		.profile = {profile, sizeof(profile) - 1u},
		.local_evidence = &local_evidence,
		.local_evidence_count = 1u,
	};
	struct composite_eat_der_certificate certificate = {certificate_bytes,
		sizeof(certificate_bytes)};
	struct composite_eat_attestation_identity identity = {NULL, 0u};
	struct test_context context = {.evidence = &evidence, .identity = &identity};
	const struct example_evidence_provider evidence_provider = {
		.context = &context,
		.begin_snapshot = begin_snapshot,
		.end_snapshot = end_snapshot,
	};
	const struct example_attestation_provider attestation_provider = {
		.context = &context,
		.begin_identity = begin_identity,
		.hash_start_sha384 = hash_start_sha384,
		.hash_update = hash_update,
		.hash_finish = hash_finish,
		.hash_abort = hash_abort,
		.sign_es384_digest = sign_es384_digest,
		.end_identity = end_identity,
	};
	struct composite_eat_workspace *workspace = 
		(struct composite_eat_workspace *)malloc(sizeof(struct composite_eat_workspace));
	uint8_t *response;
	size_t response_length = 0u;
	size_t index;

	if (resp_buf == NULL || workspace == NULL) {
		LOG_ERR("Failed to allocate composite EAT buffers");
		free(resp_buf);
		free(workspace);
		return MCTP_ERROR;
	}

	response = resp_buf + sizeof(*req);

	if (composite_eat_generation_request_decode(req->vdm, len - sizeof(*req), &request) !=
			COMPOSITE_EAT_OK) {
		LOG_ERR("Failed to decode composite EAT generation request");
		return MCTP_ERROR;
	}

	// request.version = COMPOSITE_EAT_GENERATION_REQUEST_VERSION;
	// request.nonce_length = COMPOSITE_EAT_MIN_NONCE_LENGTH;

	result = example_generate_composite_eat(&attestation_provider, &evidence_provider, &request,
				workspace, response, COMPOSITE_EAT_MAX_RESPONSE_LENGTH - sizeof(*req),
				&response_length);

	if (result != COMPOSITE_EAT_OK) {
		LOG_ERR("Failed to generate composite EAT: %d", result);
		return MCTP_ERROR;
	}

	memcpy(resp_buf, req, sizeof(*req));
	// memcpy(resp_buf + sizeof(*req), response, response_length);

	free(workspace);

	result = mctp_send_msg((mctp *)mctp_p, resp_buf, sizeof(struct mctp_vdm_pci_req) + response_length,
			ext_params);
	free(resp_buf);
	return result;
}
