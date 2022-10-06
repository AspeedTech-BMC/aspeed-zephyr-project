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
	/* Deserialize */
	LOG_HEXDUMP_INF(req_msg->buffer.data, req_msg->buffer.size, "NEGOTIATE_ALGORITHMS DATA:");
	spdm_buffer_get_u16(&req_msg->buffer, &context->remote.algorithms.length); 
	spdm_buffer_get_u8(&req_msg->buffer, &context->remote.algorithms.measurement_spec_sel);
	spdm_buffer_get_u8(&req_msg->buffer, &context->remote.algorithms.other_param_sel);
	spdm_buffer_get_u32(&req_msg->buffer, &context->remote.algorithms.base_asym_sel);
	spdm_buffer_get_u32(&req_msg->buffer, &context->remote.algorithms.base_hash_sel);
	spdm_buffer_get_reserved(&req_msg->buffer, 12);
	spdm_buffer_get_u8(&req_msg->buffer, &context->remote.algorithms.ext_asym_sel_count); /* A */
	spdm_buffer_get_u8(&req_msg->buffer, &context->remote.algorithms.ext_hash_sel_count); /* E */
	spdm_buffer_get_reserved(&req_msg->buffer, 2);
	for (size_t i=0; i < context->remote.algorithms.ext_asym_sel_count; ++i)
		spdm_buffer_get_u32(&req_msg->buffer, &context->remote.algorithms.ext_asym_sel[i]);
	for (size_t i=0; i < context->remote.algorithms.ext_hash_sel_count; ++i)
		spdm_buffer_get_u32(&req_msg->buffer, &context->remote.algorithms.ext_hash_sel[i]);

	/* Compare with local algorithm */

	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	/* Serialize the result */
	rsp_msg->header.request_response_code = SPDM_RSP_ALGORITHMS;
	rsp_msg->header.param1 = 0; /* N: Number of algorithm in RespAlgStruct */
	rsp_msg->header.param2 = 0;
	spdm_buffer_init(&rsp_msg->buffer,
			36
			+ 4 * context->local.algorithms.ext_asym_sel_count /* A' */
			+ 4 * context->local.algorithms.ext_hash_sel_count /* E' */
			+ 0 /* Sum sizeof(RespAlgStruct) */
			);
	spdm_buffer_append_u16(&rsp_msg->buffer, 0); /* Placeholder, update later */
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.algorithms.measurement_spec_sel);
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.algorithms.other_param_sel);
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.algorithms.measurement_hash_algo);
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.algorithms.base_asym_sel);
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.algorithms.base_hash_sel);
	spdm_buffer_append_reserved(&rsp_msg->buffer, 12);
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.algorithms.ext_asym_sel_count); /* A' */
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.algorithms.ext_hash_sel_count); /* E' */
	spdm_buffer_append_reserved(&rsp_msg->buffer, 2);
	for (size_t i=0; i < context->local.algorithms.ext_asym_sel_count; ++i)
		spdm_buffer_append_u32(&req_msg->buffer, context->local.algorithms.ext_asym_sel[i]);
	for (size_t i=0; i < context->local.algorithms.ext_hash_sel_count; ++i)
		spdm_buffer_append_u32(&req_msg->buffer, context->local.algorithms.ext_hash_sel[i]);

	*((uint8_t *)rsp_msg->buffer.data) = (rsp_msg->buffer.write_ptr + 4) & 0xff;
	*((uint8_t *)rsp_msg->buffer.data + 1) = ((rsp_msg->buffer.write_ptr + 4) >> 8) & 0xff;
	spdm_context_update_m1m2_hash(context, req_msg, rsp_msg);

	return 0;
}
