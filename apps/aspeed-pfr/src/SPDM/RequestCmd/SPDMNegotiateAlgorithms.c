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

	req_msg.header.spdm_version = SPDM_VERSION;
	req_msg.header.request_response_code = SPDM_REQ_NEGOTIATE_ALGORITHMS;
	req_msg.header.param1 = 0; /* N: Number of algorithms in ReqAlgStruct */
	req_msg.header.param2 = 0; /* Reserved */

	/* Serialize local algorithm to buffer */
	spdm_buffer_init(&req_msg.buffer,
			32
			+ 4 * context->local.algorithms.ext_asym_sel_count /* A */
			+ 4 * context->local.algorithms.ext_hash_sel_count /* E */
			+ 0 /* Sum sizeof(ReqAlgStruct) */
			);

	/* TODO: Update after serialized? */
	spdm_buffer_append_u16(&req_msg.buffer, context->local.algorithms.length); 
	spdm_buffer_append_u8(&req_msg.buffer, context->local.algorithms.measurement_spec_sel);
	spdm_buffer_append_u8(&req_msg.buffer, context->local.algorithms.other_param_sel);
	spdm_buffer_append_u32(&req_msg.buffer, context->local.algorithms.base_asym_sel);
	spdm_buffer_append_u32(&req_msg.buffer, context->local.algorithms.base_hash_sel);
	spdm_buffer_append_reserved(&req_msg.buffer, 12);
	spdm_buffer_append_u8(&req_msg.buffer, context->local.algorithms.ext_asym_sel_count); /* A */
	spdm_buffer_append_u8(&req_msg.buffer, context->local.algorithms.ext_hash_sel_count); /* E */
	spdm_buffer_append_reserved(&req_msg.buffer, 2);
	for (size_t i=0; i < context->local.algorithms.ext_asym_sel_count; ++i)
		spdm_buffer_append_u32(&req_msg.buffer, context->local.algorithms.ext_asym_sel[i]);
	for (size_t i=0; i < context->local.algorithms.ext_hash_sel_count; ++i)
		spdm_buffer_append_u32(&req_msg.buffer, context->local.algorithms.ext_hash_sel[i]);
	/* TODO: Append ReqAlgStruct */

	((uint8_t *)req_msg.buffer.data)[0] = (req_msg.buffer.write_ptr + 4) & 0xFF;
	((uint8_t *)req_msg.buffer.data)[1] = ((req_msg.buffer.write_ptr + 4) >> 8) & 0xFF;
	spdm_send_request(ctx, &req_msg, &rsp_msg);

	/* Deserialize remote algorithm from buffer */
	spdm_buffer_get_u16(&rsp_msg.buffer, &context->remote.algorithms.length);
	spdm_buffer_get_u8(&rsp_msg.buffer, &context->remote.algorithms.measurement_spec_sel);
	spdm_buffer_get_u8(&rsp_msg.buffer, &context->remote.algorithms.other_param_sel);
	spdm_buffer_get_u32(&rsp_msg.buffer, &context->remote.algorithms.measurement_hash_algo);
	spdm_buffer_get_u32(&rsp_msg.buffer, &context->remote.algorithms.base_asym_sel);
	spdm_buffer_get_u32(&rsp_msg.buffer, &context->remote.algorithms.base_hash_sel);
	spdm_buffer_get_reserved(&rsp_msg.buffer, 12);
	spdm_buffer_get_u8(&rsp_msg.buffer, &context->remote.algorithms.ext_asym_sel_count); /* A' */
	spdm_buffer_get_u8(&rsp_msg.buffer, &context->remote.algorithms.ext_hash_sel_count); /* E' */
	spdm_buffer_get_reserved(&rsp_msg.buffer, 2);
	for (size_t i=0; i < context->remote.algorithms.ext_asym_sel_count; ++i)
		spdm_buffer_get_u32(&req_msg.buffer, &context->remote.algorithms.ext_asym_sel[i]);
	for (size_t i=0; i < context->remote.algorithms.ext_hash_sel_count; ++i)
		spdm_buffer_get_u32(&req_msg.buffer, &context->remote.algorithms.ext_hash_sel[i]);
	/* TODO: Append ReqAlgStruct */

	LOG_HEXDUMP_INF(&rsp_msg.header, sizeof(rsp_msg.header), "ALGORITHMS HEADER:");
	LOG_HEXDUMP_INF(rsp_msg.buffer.data, rsp_msg.buffer.size, "ALGORITHMS DATA:");
	
#if defined(SPDM_TRANSCRIPT)
	/* Construct transcript for challenge */
	spdm_buffer_resize(&context->message_a,
			context->message_a.size + 
			req_msg.buffer.size + sizeof(req_msg.header) +
			rsp_msg.buffer.size + sizeof(rsp_msg.header));
	spdm_buffer_append_array(&context->message_a, &req_msg.header, sizeof(req_msg.header));
	spdm_buffer_append_array(&context->message_a, req_msg.buffer.data, req_msg.buffer.size);
	spdm_buffer_append_array(&context->message_a, &rsp_msg.header, sizeof(rsp_msg.header));
	spdm_buffer_append_array(&context->message_a, rsp_msg.buffer.data, rsp_msg.buffer.size);
#else
	spdm_context_update_m1m2_hash(context, &req_msg, &rsp_msg);
#endif


	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return 0;
}
