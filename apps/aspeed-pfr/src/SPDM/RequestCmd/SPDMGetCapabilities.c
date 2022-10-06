/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_get_capabilities(void *ctx) 
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;

	req_msg.header.spdm_version = SPDM_VERSION;
	req_msg.header.request_response_code = SPDM_REQ_GET_CAPABILITIES;
	req_msg.header.param1 = 0;
	req_msg.header.param2 = 0;

#if 1
	spdm_buffer_init(&req_msg.buffer, 0);
#else
	// SPDM 1.2
	spdm_buffer_init(&req_msg.buffer, 16);
	spdm_buffer_append_reserved(&req_msg.buffer, 1);
	spdm_buffer_append_u8(&req_msg.buffer, context->local.capabilities.ct_exponent);
	spdm_buffer_append_reserved(&req_msg.buffer, 2);
	spdm_buffer_append_u32(&req_msg.buffer, context->local.capabilities.flags);
	spdm_buffer_append_u32(&req_msg.buffer, context->local.capabilities.data_transfer_size);
	spdm_buffer_append_u32(&req_msg.buffer, context->local.capabilities.max_spdm_msg_size);
#endif
	spdm_send_request(ctx, &req_msg, &rsp_msg);

	spdm_buffer_get_reserved(&rsp_msg.buffer, 1);
	spdm_buffer_get_u8(&rsp_msg.buffer, &context->remote.capabilities.ct_exponent);
	spdm_buffer_get_reserved(&rsp_msg.buffer, 2);
	spdm_buffer_get_u32(&rsp_msg.buffer, &context->remote.capabilities.flags);
	spdm_buffer_get_u32(&rsp_msg.buffer, &context->remote.capabilities.data_transfer_size);
	spdm_buffer_get_u32(&rsp_msg.buffer, &context->remote.capabilities.max_spdm_msg_size);

	LOG_HEXDUMP_INF(&rsp_msg.header, sizeof(rsp_msg.header), "CAPABILITIES HEADER:");
	LOG_HEXDUMP_INF(rsp_msg.buffer.data, rsp_msg.buffer.size, "CAPABILITIES DATA:");

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

