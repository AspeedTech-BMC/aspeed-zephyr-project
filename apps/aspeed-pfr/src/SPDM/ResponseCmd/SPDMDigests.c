/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"

#include <mbedtls/sha512.h>

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_handle_get_digests(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	int ret;
	/* Deserialize */
	LOG_HEXDUMP_INF(&req_msg->header, sizeof(req_msg->header), "GET_DIGESTS HEADER:");
	if (req_msg->header.spdm_version != SPDM_VERSION) {
		LOG_ERR("Unsupported header SPDM_VERSION %x", req_msg->header.spdm_version);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_MAJOR_VERSION_MISMATCH;
		ret = -1;
		goto cleanup;
	}

	/* Serialize the result */
	rsp_msg->header.request_response_code = SPDM_RSP_DIGESTS;
	rsp_msg->header.param1 = 0;
	rsp_msg->header.param2 = context->local.certificate.slot_mask;

	uint8_t slot_mask, cert_count = 0;
	slot_mask = context->local.certificate.slot_mask;
	while (slot_mask) {
		cert_count++;
		slot_mask >>= 1;
	}
	LOG_INF("SlotMask=%x Count=%d", context->local.certificate.slot_mask, cert_count);
	spdm_buffer_init(&rsp_msg->buffer, cert_count * spdm_context_base_hash_size(context));

	slot_mask = context->local.certificate.slot_mask;
	cert_count = 0;
	while (slot_mask) {
		if (slot_mask & 0x01 && context->local.certificate.certs[cert_count].data != NULL) {
			// Certificate exists, calculate the digest with Certificate Chain Format
			// [0:1] Length: including all fields in this table
			// [2:3] Reserved
			// [4:H] Root Hash
			// [4+H:...] One or more ASN.1 DER-encoded X.509 v3 certificates
			//           where the first certificate is signed by the Root
			//           Certificate or is the Root Certificate itself and each
			//           subsequent certificate is signed by the preceding
			//           certificate. The last certificate is the leaf certificate.
			//           This field is big endian.
			uint8_t hash[48];
			mbedtls_sha512(context->local.certificate.certs[cert_count].data,
					context->local.certificate.certs[cert_count].size,
					hash,
					1 /* is384*/);
			LOG_HEXDUMP_DBG(hash, 48, "CERT DIGEST:");
			spdm_buffer_append_array(&rsp_msg->buffer, hash, spdm_context_base_hash_size(context));
		}
		cert_count++;
		slot_mask >>= 1;
	}

	spdm_context_update_m1m2_hash(context, req_msg, rsp_msg);

	ret = 0;
cleanup:
	return ret;
}
