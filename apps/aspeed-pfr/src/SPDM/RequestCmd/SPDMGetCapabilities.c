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
	int ret;

	req_msg.header.spdm_version = context->local.version.version_number_selected;
	req_msg.header.request_response_code = SPDM_REQ_GET_CAPABILITIES;
	req_msg.header.param1 = 0;
	req_msg.header.param2 = 0;

	spdm_buffer_init(&req_msg.buffer, 16);
	spdm_buffer_init(&rsp_msg.buffer, 0);

	if (context->local.version.version_number_selected == SPDM_VERSION_11) {
		// SPDM 1.1
		spdm_buffer_append_reserved(&req_msg.buffer, 1);
		spdm_buffer_append_u8(&req_msg.buffer, context->local.capabilities.ct_exponent);
		spdm_buffer_append_reserved(&req_msg.buffer, 2);
		spdm_buffer_append_u32(&req_msg.buffer, context->local.capabilities.flags);
	} else if (context->local.version.version_number_selected == SPDM_VERSION_12) {
		// SPDM 1.2
		spdm_buffer_append_reserved(&req_msg.buffer, 1);
		spdm_buffer_append_u8(&req_msg.buffer, context->local.capabilities.ct_exponent);
		spdm_buffer_append_reserved(&req_msg.buffer, 2);
		spdm_buffer_append_u32(&req_msg.buffer,
				context->local.capabilities.flags & ~(BIT(3) | BIT(4) | BIT(5)));
		spdm_buffer_append_u32(&req_msg.buffer, context->local.capabilities.data_transfer_size);
		spdm_buffer_append_u32(&req_msg.buffer, context->local.capabilities.max_spdm_msg_size);
	}
	ret = spdm_send_request(ctx, &req_msg, &rsp_msg);
	if (ret != 0) {
		LOG_ERR("GET_CAPABILITIES failed %x", ret);
		ret = -1;
		goto cleanup;
	} else if ((rsp_msg.header.spdm_version != req_msg.header.spdm_version)) {
		LOG_ERR("Unmatched header SPDM_VERSION Req %02x Rsp %02x",
				req_msg.header.spdm_version,
				rsp_msg.header.spdm_version);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.request_response_code != SPDM_RSP_CAPABILITIES) {
		LOG_ERR("Expecting CAPABILITIES message but got %02x Param[%02x,%02x]",
				rsp_msg.header.request_response_code,
				rsp_msg.header.param1,
				rsp_msg.header.param2);
		ret = -1;
		goto cleanup;
	} else if ((req_msg.header.spdm_version == SPDM_VERSION_10 && rsp_msg.buffer.write_ptr != 8) ||
			(req_msg.header.spdm_version == SPDM_VERSION_11 && rsp_msg.buffer.write_ptr != 8) ||
			(req_msg.header.spdm_version == SPDM_VERSION_12 && rsp_msg.buffer.write_ptr != 16)) {
		LOG_ERR("CAPABILITIES message length incorrect VERSION=%02x LEGNTH=%d",
				req_msg.header.spdm_version, rsp_msg.buffer.write_ptr);
		ret = -1;
		goto cleanup;
	}

	spdm_buffer_get_reserved(&rsp_msg.buffer, 1);
	spdm_buffer_get_u8(&rsp_msg.buffer, &context->remote.capabilities.ct_exponent);
	spdm_buffer_get_reserved(&rsp_msg.buffer, 2);
	spdm_buffer_get_u32(&rsp_msg.buffer, &context->remote.capabilities.flags);
#if 0
	// SPDM 1.2
	spdm_buffer_get_u32(&rsp_msg.buffer, &context->remote.capabilities.data_transfer_size);
	spdm_buffer_get_u32(&rsp_msg.buffer, &context->remote.capabilities.max_spdm_msg_size);
#endif

	LOG_HEXDUMP_INF(&rsp_msg.header, sizeof(rsp_msg.header), "CAPABILITIES HEADER:");
	LOG_HEXDUMP_DBG(rsp_msg.buffer.data, rsp_msg.buffer.write_ptr, "CAPABILITIES DATA:");

	/* Construct transcript for challenge */
	spdm_buffer_resize(&context->message_a,
			context->message_a.size +
			req_msg.buffer.size + sizeof(req_msg.header) +
			rsp_msg.buffer.size + sizeof(rsp_msg.header));
	spdm_buffer_append_array(&context->message_a, &req_msg.header, sizeof(req_msg.header));
	spdm_buffer_append_array(&context->message_a, req_msg.buffer.data, req_msg.buffer.write_ptr);
	spdm_buffer_append_array(&context->message_a, &rsp_msg.header, sizeof(rsp_msg.header));
	spdm_buffer_append_array(&context->message_a, rsp_msg.buffer.data, rsp_msg.buffer.write_ptr);

	spdm_context_update_m1m2_hash(context, &req_msg, &rsp_msg);
	ret = 0;

cleanup:

	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return ret;
}

