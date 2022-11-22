/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <random/rand32.h>
#include <stdlib.h>

#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_challenge(void *ctx, uint8_t slot_id, uint8_t measurements)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;
	int ret;

	req_msg.header.spdm_version = SPDM_VERSION;
	req_msg.header.request_response_code = SPDM_REQ_CHALLENGE;
	req_msg.header.param1 = slot_id; // SlotID or 0xFF
	req_msg.header.param2 = measurements; // No measuments, TCB measurement, All measurement

	spdm_buffer_init(&req_msg.buffer, 32);
	spdm_buffer_init(&rsp_msg.buffer, 0);
	spdm_buffer_append_nonce(&req_msg.buffer);

	ret = spdm_send_request(context, &req_msg, &rsp_msg);
	if (ret != 0) {
		LOG_ERR("CHALLENGE failed %x", ret);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.spdm_version != SPDM_VERSION) {
		LOG_ERR("Unsupported header SPDM_VERSION %x", rsp_msg.header.spdm_version);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.request_response_code != SPDM_RSP_CHALLENGE_AUTH) {
		LOG_ERR("Expecting CHALLENGE_AUTH message but got %02x Param[%02x,%02x]",
				rsp_msg.header.request_response_code,
				rsp_msg.header.param1,
				rsp_msg.header.param2);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.buffer.write_ptr < 48 + 32 + (measurements?48:0) + 2 + 96) {
		// Exact length require to read OpaqueLength
		LOG_ERR("CHALLENGE_AUTH message length incorrect len=%d", rsp_msg.buffer.write_ptr);
		ret = -1;
		goto cleanup;
	}

	/* Verify the CHALLENGE_AUTH result 
	 * Off         Len    Name
	 *    0,         H    CertChainHash
	 *    H,        32    Nonce
	 * 32+H,         H    MeasuremenHash
	 * 32+2H,        2    OpaqueDataLength (O)
	 * 34+2H,        O    OpaqueDataData
	 * 34+2H+O, SigLen    Signature
	 */
	LOG_HEXDUMP_INF(&rsp_msg.header, 4, "CHALLENGE_AUTH HEADER:");
	LOG_HEXDUMP_DBG(rsp_msg.buffer.data, rsp_msg.buffer.write_ptr, "CHALLENGE_AUTH:");

	// Verify the CHALLENGE_AUTH signature
	mbedtls_mpi r, s;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	uint8_t hash[48];

	mbedtls_mpi_read_binary(&r, (uint8_t *)rsp_msg.buffer.data + rsp_msg.buffer.write_ptr - 96, 48);
	mbedtls_mpi_read_binary(&s, (uint8_t *)rsp_msg.buffer.data + rsp_msg.buffer.write_ptr - 48, 48);

	rsp_msg.buffer.write_ptr -= 96;
	spdm_context_update_m1m2_hash(context, &req_msg, &rsp_msg);
	rsp_msg.buffer.write_ptr += 96;
	mbedtls_sha512_finish(&context->m1m2_context, hash);
	spdm_context_reset_m1m2_hash(context);

	mbedtls_x509_crt *cur = &context->remote.certificate.certs[slot_id].chain;
	size_t cert_index = 0;
	while (cur) {
		++cert_index;
		if (cur->next != NULL)
			cur = cur->next;
		else {
#if 0
			LOG_INF("Found LEAF_CERT[%d]", cert_index);
			char *buf = malloc(CONFIG_LOG_STRDUP_MAX_STRING);
			ret = mbedtls_x509_crt_info(buf, CONFIG_LOG_STRDUP_MAX_STRING-1, "\r", cur);
			if (ret > 0) {
				buf[ret] = '\0';
				LOG_INF("Certificate[%d][%d] info:\n%s", slot_id, cert_index, log_strdup(buf));
			}
			free(buf);
#endif
			break;
		}
	}

	ret = mbedtls_ecdsa_verify(
			&mbedtls_pk_ec(cur->pk)->MBEDTLS_PRIVATE(grp),
			hash, spdm_context_base_hash_size(context),
			&mbedtls_pk_ec(cur->pk)->MBEDTLS_PRIVATE(Q),
			&r, &s);
	LOG_INF("CHALLENG_AUTH SIGNATURE VERIFY ret=%x", -ret);
	if (ret < 0) {
		LOG_HEXDUMP_ERR(hash, 48, "Requester M2 hash:");
		ret = -1;
	} 
	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);

cleanup:
	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return ret;
}
