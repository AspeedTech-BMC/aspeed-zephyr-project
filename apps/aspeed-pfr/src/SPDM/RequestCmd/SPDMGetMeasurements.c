/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <random/rand32.h>

#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_get_measurements(void *ctx, uint8_t request_attribute, uint8_t measurement_operation, uint8_t *number_of_blocks)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;

	req_msg.header.spdm_version = SPDM_VERSION;
	req_msg.header.request_response_code = SPDM_REQ_GET_MEASUREMENTS;
	req_msg.header.param1 = request_attribute; // GET_MEASUREMENTS request attributes : NL
	req_msg.header.param2 = measurement_operation;

	spdm_buffer_init(&req_msg.buffer, (req_msg.header.param1 ? 32 : 0) /* SPDM 1.2: + 1*/);

	if (req_msg.header.param1) {
		// nonce(32)
		spdm_buffer_append_nonce(&req_msg.buffer);
	}

#if 0
	// TODO: SPDM 1.2 Requested Slot ID
	spdm_buffer_append_u8(&req_msg.buffer, 0);
#endif
	spdm_send_request(context, &req_msg, &rsp_msg);

	if (rsp_msg.header.request_response_code != SPDM_RSP_MEASUREMENTS) {
		LOG_ERR("GET MEASUREMENTS FAILED Error Code %02x %02x",
				rsp_msg.header.param1, rsp_msg.header.param2);
		return -1;
	}

	if (measurement_operation == SPDM_MEASUREMENT_OPERATION_TOTAL_NUMBER) {
		*number_of_blocks = rsp_msg.header.param1;
	} else if (measurement_operation == SPDM_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
		*number_of_blocks = rsp_msg.header.param1;
	}

	LOG_HEXDUMP_INF(&rsp_msg.header, 4, "MEASUREMENTS Header:");
	LOG_HEXDUMP_INF(rsp_msg.buffer.data, rsp_msg.buffer.size, "MEASUREMENTS:");

	/* Process L1L2 hash */
	if (request_attribute == 0x00) {
		spdm_context_update_l1l2_hash(context, &req_msg, &rsp_msg);	
	} else if (request_attribute == 0x01) {
		rsp_msg.buffer.write_ptr -= 96;
		spdm_context_update_l1l2_hash(context, &req_msg, &rsp_msg);	
		rsp_msg.buffer.write_ptr += 96;
		
		/* Verify signature */
		uint8_t hash[48];
		
		mbedtls_sha512_finish(&context->l1l2_context, hash);
		spdm_context_reset_l1l2_hash(context);

		mbedtls_mpi r, s;
		mbedtls_mpi_init(&r);
		mbedtls_mpi_init(&s);
		int ret;

		mbedtls_mpi_read_binary(&r, (uint8_t *)rsp_msg.buffer.data + rsp_msg.buffer.write_ptr - 96, 48);
		mbedtls_mpi_read_binary(&s, (uint8_t *)rsp_msg.buffer.data + rsp_msg.buffer.write_ptr - 48, 48);

		ret = mbedtls_ecdsa_verify(&context->key_pair.MBEDTLS_PRIVATE(grp),
				hash, spdm_context_base_hash_size(context),
				&context->key_pair.MBEDTLS_PRIVATE(Q),
				&r, &s);
		LOG_INF("GET_MEASUREMENT SIGNATURE VERIFY ret=%x", -ret);
		if (ret < 0) {
			LOG_HEXDUMP_ERR(hash, 48, "Requester L2 hash:");
		}
		mbedtls_mpi_free(&s);
		mbedtls_mpi_free(&r);
	}
	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return 0;
}

