/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_negotiate_algorithms(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;
	int ret;

	req_msg.header.spdm_version = context->local.version.version_number_selected;
	req_msg.header.request_response_code = SPDM_REQ_NEGOTIATE_ALGORITHMS;
	req_msg.header.param1 = 0; /* N: Number of algorithms in ReqAlgStruct */
	req_msg.header.param2 = 0; /* Reserved */

	/* Serialize local algorithm to buffer */
	spdm_buffer_init(&req_msg.buffer,
			32
			+ 4 * 0 /* context->local.algorithms.ext_asym_sel_count A */
			+ 4 * 0 /* context->local.algorithms.ext_hash_sel_count E */
			+ 4
			);
	spdm_buffer_init(&rsp_msg.buffer, 0);

	/* Update after serialized */
	spdm_buffer_append_u16(&req_msg.buffer, context->local.algorithms.length); 
	spdm_buffer_append_u8(&req_msg.buffer, context->local.algorithms.measurement_spec_sel);
	spdm_buffer_append_u8(&req_msg.buffer, context->local.algorithms.other_param_sel);
	spdm_buffer_append_u32(&req_msg.buffer, context->local.algorithms.base_asym_sel);
	spdm_buffer_append_u32(&req_msg.buffer, context->local.algorithms.base_hash_sel);
	spdm_buffer_append_reserved(&req_msg.buffer, 12);

	/* AlgStruct Not supported */
#if 1
	spdm_buffer_append_u8(&req_msg.buffer, 0); /* A */
	spdm_buffer_append_u8(&req_msg.buffer, 0); /* E */
	spdm_buffer_append_reserved(&req_msg.buffer, 2);
#else
	spdm_buffer_append_u8(&req_msg.buffer, context->local.algorithms.ext_asym_sel_count); /* A */
	spdm_buffer_append_u8(&req_msg.buffer, context->local.algorithms.ext_hash_sel_count); /* E */
	spdm_buffer_append_reserved(&req_msg.buffer, 2);
	for (size_t i=0; i < context->local.algorithms.ext_asym_sel_count; ++i)
		spdm_buffer_append_u32(&req_msg.buffer, context->local.algorithms.ext_asym_sel[i]);
	for (size_t i=0; i < context->local.algorithms.ext_hash_sel_count; ++i)
		spdm_buffer_append_u32(&req_msg.buffer, context->local.algorithms.ext_hash_sel[i]);
#endif

	/* Update request length */
	((uint8_t *)req_msg.buffer.data)[0] = (req_msg.buffer.write_ptr + 4) & 0xFF;
	((uint8_t *)req_msg.buffer.data)[1] = ((req_msg.buffer.write_ptr + 4) >> 8) & 0xFF;

	ret = spdm_send_request(ctx, &req_msg, &rsp_msg);
	if (ret != 0) {
		LOG_ERR("NEGOTIATE_ALGORITHMS failed %x", ret);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.spdm_version != req_msg.header.spdm_version) {
		LOG_ERR("Unsupported header SPDM_VERSION %x", rsp_msg.header.spdm_version);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.request_response_code != SPDM_RSP_ALGORITHMS) {
		LOG_ERR("Expecting ALGORITHMS message but got %02x Param[%02x,%02x]",
				rsp_msg.header.request_response_code,
				rsp_msg.header.param1,
				rsp_msg.header.param2);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.buffer.write_ptr < 28) {
		LOG_ERR("ALGORITHMS message length too small %d", rsp_msg.buffer.write_ptr);
		ret = -1;
		goto cleanup;
	}

	/* Deserialize remote algorithm from buffer */
	uint16_t algorithms_length;
	uint8_t measurement_spec_sel;
	uint32_t measurement_hash_algo;
	uint32_t base_asym_sel;
	uint32_t base_hash_sel;

	spdm_buffer_get_u16(&rsp_msg.buffer, &algorithms_length);
	if (algorithms_length != rsp_msg.buffer.write_ptr + 4) {
		LOG_ERR("ALGORITHMS message length not match expect %d got %d",
				rsp_msg.buffer.write_ptr + 4, algorithms_length);
		ret = -1;
		goto cleanup;
	}

	spdm_buffer_get_u8(&rsp_msg.buffer, &measurement_spec_sel);
	if ((measurement_spec_sel & SPDM_MEASUREMENT_BLOCK_DMTF_SPEC) == 0) {
		LOG_ERR("ALGORITHMS MeasurmentSpecificationSel=%02x not consent",
				measurement_spec_sel);
		ret = -1;
		goto cleanup;
	}

	// SPDM 1.2 reserved for OtherParam
	spdm_buffer_get_reserved(&rsp_msg.buffer, 1);

	spdm_buffer_get_u32(&rsp_msg.buffer, &measurement_hash_algo);
	if ((measurement_hash_algo & SPDM_ALGORITHMS_MEAS_HASH_TPM_ALG_SHA_384) == 0) {
		LOG_ERR("ALGORITHMS MeasurementHashAlog not consent %08x",
				measurement_hash_algo);
		ret = -1;
		goto cleanup;
	}

	spdm_buffer_get_u32(&rsp_msg.buffer, &base_asym_sel);
	if ((base_asym_sel & SPDM_ALGORITHMS_BASE_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384) == 0) {
		LOG_ERR("ALGORITHMS BaseAsymSel not consent %08x", base_asym_sel);
		ret = -1;
		goto cleanup;
	}
	spdm_buffer_get_u32(&rsp_msg.buffer, &base_hash_sel);
	if ((base_hash_sel & SPDM_ALGORITHMS_BASE_HASH_TPM_ALG_SHA_384) == 0) {
		LOG_ERR("ALGORITHMS BaseHashSel not consent %08x", base_hash_sel);
		ret = -1;
		goto cleanup;
	}

	/* All good now, save to context */
	context->remote.algorithms.length = algorithms_length;
	context->remote.algorithms.measurement_spec_sel = measurement_spec_sel;
	context->remote.algorithms.measurement_hash_algo = measurement_hash_algo;
	context->remote.algorithms.base_asym_sel = base_asym_sel;
	context->remote.algorithms.base_hash_sel = base_hash_sel;

	spdm_buffer_get_reserved(&rsp_msg.buffer, 12);

	/* Not supported */
#if 0
	spdm_buffer_get_u8(&rsp_msg.buffer, &context->remote.algorithms.ext_asym_sel_count); /* A' */
	spdm_buffer_get_u8(&rsp_msg.buffer, &context->remote.algorithms.ext_hash_sel_count); /* E' */
	spdm_buffer_get_reserved(&rsp_msg.buffer, 2);
	for (size_t i=0; i < context->remote.algorithms.ext_asym_sel_count; ++i)
		spdm_buffer_get_u32(&req_msg.buffer, &context->remote.algorithms.ext_asym_sel[i]);
	for (size_t i=0; i < context->remote.algorithms.ext_hash_sel_count; ++i)
		spdm_buffer_get_u32(&req_msg.buffer, &context->remote.algorithms.ext_hash_sel[i]);
#endif
	ret = 0;

	/* Construct transcript for challenge */
	spdm_buffer_resize(&context->message_a,
			context->message_a.size + 
			req_msg.buffer.write_ptr + sizeof(req_msg.header) +
			rsp_msg.buffer.write_ptr + sizeof(rsp_msg.header));
	spdm_buffer_append_array(&context->message_a, &req_msg.header, sizeof(req_msg.header));
	spdm_buffer_append_array(&context->message_a, req_msg.buffer.data, req_msg.buffer.write_ptr);
	spdm_buffer_append_array(&context->message_a, &rsp_msg.header, sizeof(rsp_msg.header));
	spdm_buffer_append_array(&context->message_a, rsp_msg.buffer.data, rsp_msg.buffer.write_ptr);

	spdm_context_update_m1m2_hash(context, &req_msg, &rsp_msg);

cleanup:

	LOG_HEXDUMP_INF(&rsp_msg.header, sizeof(rsp_msg.header), "ALGORITHMS HEADER:");
	LOG_HEXDUMP_INF(rsp_msg.buffer.data, rsp_msg.buffer.size, "ALGORITHMS DATA:");

	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return ret;
}
