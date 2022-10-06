/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <random/rand32.h>

#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_challenge(void *ctx, uint8_t slot_id, uint8_t measurements)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;

	req_msg.header.spdm_version = SPDM_VERSION;
	req_msg.header.request_response_code = SPDM_REQ_CHALLENGE;
	req_msg.header.param1 = slot_id; // SlotID or 0xFF
	req_msg.header.param2 = measurements; // No measuments, TCB measurement, All measurement

	spdm_buffer_init(&req_msg.buffer, 32);
	spdm_buffer_append_nonce(&req_msg.buffer);

	spdm_send_request(context, &req_msg, &rsp_msg);

	/* Verify the CHALLENGE_AUTH result 
	 * Off         Len    Name
	 *    0,         H    CertChainHash
	 *    H,        32    Nonce
	 * 32+H,         H    MeasuremenHash
	 * 32+2H,        2    OpaqueDataLength (O)
	 * 34+2H,        O    OpaqueDataData
	 * 34+2H+O, SigLen    Signature
	 */
	LOG_HEXDUMP_INF(rsp_msg.buffer.data, rsp_msg.buffer.size, "CHALLENGE_AUTH:");

	// Verify the CHALLENGE_AUTH signature
	mbedtls_mpi r, s;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	int ret;

	mbedtls_mpi_read_binary(&r, (uint8_t *)rsp_msg.buffer.data + rsp_msg.buffer.write_ptr - 96, 48);
	mbedtls_mpi_read_binary(&s, (uint8_t *)rsp_msg.buffer.data + rsp_msg.buffer.write_ptr - 48, 48);

	uint8_t hash[48];

	rsp_msg.buffer.write_ptr -= 96;
	spdm_context_update_m1m2_hash(context, &req_msg, &rsp_msg);
	rsp_msg.buffer.write_ptr += 96;
	mbedtls_sha512_finish(&context->m1m2_context, hash);
	spdm_context_reset_m1m2_hash(context);

	ret = mbedtls_ecdsa_verify(&context->key_pair.MBEDTLS_PRIVATE(grp),
			hash, spdm_context_base_hash_size(context),
			&context->key_pair.MBEDTLS_PRIVATE(Q),
			&r, &s);
	LOG_INF("CHALLENG_AUTH SIGNATURE VERIFY ret=%x", -ret);
	if (ret < 0) {
		LOG_HEXDUMP_ERR(hash, 48, "Requester M2 hash:");
	} 
	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);
	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return ret;
}
