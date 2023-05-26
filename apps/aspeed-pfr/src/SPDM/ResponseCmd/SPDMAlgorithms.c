/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_handle_negotiate_algorithms(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	int ret = -1;

	uint16_t length;
	uint8_t measurement_spec_sel;
	uint32_t base_asym_sel;
	uint32_t base_hash_sel;

	LOG_HEXDUMP_INF(req_msg->buffer.data, req_msg->buffer.size, "NEGOTIATE_ALGORITHMS DATA:");

	if (req_msg->header.spdm_version != SPDM_VERSION_10 &&
			req_msg->header.spdm_version != SPDM_VERSION_11 &&
			req_msg->header.spdm_version != SPDM_VERSION_12) {
		LOG_ERR("Unsupported header SPDM_VERSION %x", req_msg->header.spdm_version);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_MAJOR_VERSION_MISMATCH;
		goto cleanup;
	}

	spdm_buffer_get_u16(&req_msg->buffer, &length);
	if (req_msg->buffer.write_ptr + 4 != length) {
		LOG_ERR("NEGOTIATE_ALGORITHMS message length incorrect expect %d got %d",
				length, req_msg->buffer.write_ptr + 4);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
		goto cleanup;
	}

	spdm_buffer_get_u8(&req_msg->buffer, &measurement_spec_sel);
	if ((measurement_spec_sel & SPDM_MEASUREMENT_BLOCK_DMTF_SPEC) == 0) {
		LOG_ERR("NEGOTIATE_ALGORITHMS MeasurmentSpecificationSel=%02x not consent",
				measurement_spec_sel);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
		goto cleanup;
	}

	if (req_msg->header.spdm_version == SPDM_VERSION_10 || req_msg->header.spdm_version == SPDM_VERSION_11) {
		spdm_buffer_get_reserved(&req_msg->buffer, 1);
	} else if (req_msg->header.spdm_version >= SPDM_VERSION_12) {
		spdm_buffer_get_u8(&req_msg->buffer, &context->remote.algorithms.other_param_sel);
	}

	spdm_buffer_get_u32(&req_msg->buffer, &base_asym_sel);
	if ((base_asym_sel & SPDM_ALGORITHMS_BASE_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384) == 0) {
		LOG_ERR("NEGOTIATE_ALGORITHMS BaseAsym=%08x not consent",
				base_asym_sel);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
		goto cleanup;
	}
	spdm_buffer_get_u32(&req_msg->buffer, &base_hash_sel);
	if ((base_hash_sel & SPDM_ALGORITHMS_BASE_HASH_TPM_ALG_SHA_384) == 0) {
		LOG_ERR("NEGOTIATE_ALGORITHMS BaseHash=%08x not consent",
				base_hash_sel);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
		goto cleanup;
	}
	spdm_buffer_get_reserved(&req_msg->buffer, 12);

	context->remote.algorithms.length = length;
	context->remote.algorithms.measurement_spec_sel = measurement_spec_sel;
	context->remote.algorithms.base_asym_sel =
		base_asym_sel & SPDM_ALGORITHMS_BASE_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
	context->remote.algorithms.base_hash_sel =
		base_hash_sel & SPDM_ALGORITHMS_BASE_HASH_TPM_ALG_SHA_384;

	if (req_msg->header.spdm_version >= SPDM_VERSION_11) {
		spdm_buffer_get_u8(&req_msg->buffer, &context->remote.algorithms.ext_asym_sel_count); /* A */
		spdm_buffer_get_u8(&req_msg->buffer, &context->remote.algorithms.ext_hash_sel_count); /* E */
		spdm_buffer_get_reserved(&req_msg->buffer, 2);
		for (size_t i=0; i < context->remote.algorithms.ext_asym_sel_count; ++i) {
			// [0]   Registry ID
			// [1]   Reserved
			// [2:3] AlgorithmID
			spdm_buffer_get_u32(&req_msg->buffer, &context->remote.algorithms.ext_asym_sel[i]);
		}
		for (size_t i=0; i < context->remote.algorithms.ext_hash_sel_count; ++i) {
			// [0]   Registry ID
			// [1]   Reserved
			// [2:3] AlgorithmID
			spdm_buffer_get_u32(&req_msg->buffer, &context->remote.algorithms.ext_hash_sel[i]);
		}
		/* ReqAlgStruct */
		uint8_t alg_type;
		// Type of algorithm.
		// 0 and 1. Reserved.
		// 2. DHE.
		// 3. AEADCipherSuite.
		// 4. ReqBaseAsymAlg.
		// 5. KeySchedule.
		// All other values reserved
		spdm_buffer_get_u8(&req_msg->buffer, &alg_type);
		if (alg_type <= 1 || alg_type > 5) {
			LOG_ERR("ReqAlgStruct.AlgType incorrect %02x", alg_type);
			rsp_msg->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
			goto cleanup;
		}

		uint8_t alg_count;
		// AlgCount:
		// Bit[7:4] Number of bytes required to describe Requester supported SPDM
		//          enumerated fixed algorithms (= FixedAlgCount ). 
		//          FixedAlgCount + 2 shall be a multiple of 4.
		// Bit[3:0] Number of Requester-supported extended algorithms (= ExtAlgCount )
		spdm_buffer_get_u8(&req_msg->buffer, &alg_count);
		if ( (((alg_count & 0xf0) >> 4) + 2) % 4 != 0) {
			LOG_ERR("ReqAlgStruct.AlgCount incorrect %02x", alg_count);
			rsp_msg->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
			goto cleanup;
		}

		uint16_t alg_supported;
		spdm_buffer_get_u16(&req_msg->buffer, &alg_supported);

		for (size_t i=0; i < (size_t)(alg_count & 0x0f); ++i) {
			uint32_t alg_external;
			spdm_buffer_get_u32(&req_msg->buffer, &alg_external);
		}

	}

	/* Compare with local algorithm */
	/* Serialize the result */
	rsp_msg->header.spdm_version = req_msg->header.spdm_version;
	rsp_msg->header.request_response_code = SPDM_RSP_ALGORITHMS;
	rsp_msg->header.param1 = 0; /* N: Number of algorithm in RespAlgStruct */
	rsp_msg->header.param2 = 0;
	spdm_buffer_init(&rsp_msg->buffer,
			36
			+ 4 * 0 /* context->local.algorithms.ext_asym_sel_count  A' */
			+ 4 * 0 /* context->local.algorithms.ext_hash_sel_count  E' */
			+ 0 /* Sum sizeof(RespAlgStruct) */
			);
	spdm_buffer_append_u16(&rsp_msg->buffer, 0); /* Placeholder, update later */
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.algorithms.measurement_spec_sel);
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.algorithms.other_param_sel);
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.algorithms.measurement_hash_algo);
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.algorithms.base_asym_sel);
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.algorithms.base_hash_sel);
	spdm_buffer_append_reserved(&rsp_msg->buffer, 12);
#if 1
	/* AlgStruct not supported */
	spdm_buffer_append_u8(&rsp_msg->buffer, 0); /* A' */
	spdm_buffer_append_u8(&rsp_msg->buffer, 0); /* E' */
	spdm_buffer_append_reserved(&rsp_msg->buffer, 2);
#else
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.algorithms.ext_asym_sel_count); /* A' */
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.algorithms.ext_hash_sel_count); /* E' */
	spdm_buffer_append_reserved(&rsp_msg->buffer, 2);
	for (size_t i=0; i < context->local.algorithms.ext_asym_sel_count; ++i)
		spdm_buffer_append_u32(&req_msg->buffer, context->local.algorithms.ext_asym_sel[i]);
	for (size_t i=0; i < context->local.algorithms.ext_hash_sel_count; ++i)
		spdm_buffer_append_u32(&req_msg->buffer, context->local.algorithms.ext_hash_sel[i]);
#endif
	*((uint8_t *)rsp_msg->buffer.data) = (rsp_msg->buffer.write_ptr + 4) & 0xff;
	*((uint8_t *)rsp_msg->buffer.data + 1) = ((rsp_msg->buffer.write_ptr + 4) >> 8) & 0xff;
	spdm_context_update_m1m2_hash(context, req_msg, rsp_msg);

	spdm_buffer_resize(&context->message_a,
			context->message_a.size +
			req_msg->buffer.write_ptr + sizeof(req_msg->header) +
			rsp_msg->buffer.write_ptr + sizeof(rsp_msg->header));
	spdm_buffer_append_array(&context->message_a, &req_msg->header, sizeof(req_msg->header));
	spdm_buffer_append_array(&context->message_a, req_msg->buffer.data, req_msg->buffer.write_ptr);
	spdm_buffer_append_array(&context->message_a, &rsp_msg->header, sizeof(rsp_msg->header));
	spdm_buffer_append_array(&context->message_a, rsp_msg->buffer.data, rsp_msg->buffer.write_ptr);

	LOG_HEXDUMP_INF(rsp_msg->buffer.data, rsp_msg->buffer.size, "ALGORITHMS DATA:");
	ret = 0;
cleanup:
	
	return ret;
}
