/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_handle_get_capabilities(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;

	int ret = -1;

	LOG_HEXDUMP_INF(req_msg->buffer.data, req_msg->buffer.size, "GET_CAPABILITIES DATA:");
	if (req_msg->header.spdm_version != SPDM_VERSION_10 &&
			req_msg->header.spdm_version != SPDM_VERSION_11 &&
			req_msg->header.spdm_version != SPDM_VERSION_12) {
		LOG_ERR("Unsupported header SPDM_VERSION %x", req_msg->header.spdm_version);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_MAJOR_VERSION_MISMATCH;
		ret = -1;
		goto cleanup;
	}

	/* Message length check */
	if ((req_msg->header.spdm_version == SPDM_VERSION_10 && req_msg->buffer.write_ptr != 0) ||
			(req_msg->header.spdm_version == SPDM_VERSION_11 && req_msg->buffer.write_ptr != 8) ||
			(req_msg->header.spdm_version == SPDM_VERSION_12 && req_msg->buffer.write_ptr != 16)) {
		LOG_ERR("Incorrect message length %d", req_msg->buffer.write_ptr);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
		ret = -1;
		goto cleanup;
	}

	/* SPDM 1.1 */
	if (req_msg->header.spdm_version >= SPDM_VERSION_11) {
		spdm_buffer_get_reserved(&req_msg->buffer, 1);
		spdm_buffer_get_u8(&req_msg->buffer, &context->remote.capabilities.ct_exponent);
		spdm_buffer_get_reserved(&req_msg->buffer, 2);
		spdm_buffer_get_u32(&req_msg->buffer, &context->remote.capabilities.flags);
	}

	/* SPDM 1.2 */
	if (req_msg->header.spdm_version >= SPDM_VERSION_12) {
		spdm_buffer_get_u32(&req_msg->buffer, &context->remote.capabilities.data_transfer_size);
		spdm_buffer_get_u32(&req_msg->buffer, &context->remote.capabilities.max_spdm_msg_size);
	}

	/* Set the flags according to *_CAP: serializer */
	rsp_msg->header.spdm_version = req_msg->header.spdm_version;
	rsp_msg->header.request_response_code = SPDM_RSP_CAPABILITIES;
	rsp_msg->header.param1 = 0;
	rsp_msg->header.param2 = 0;

	spdm_buffer_init(&rsp_msg->buffer, 24);
	spdm_buffer_append_reserved(&rsp_msg->buffer, 1);
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.capabilities.ct_exponent);
	spdm_buffer_append_reserved(&rsp_msg->buffer, 2);
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.capabilities.flags);

	/* SPDM 1.2 */
	if (rsp_msg->header.spdm_version >= SPDM_VERSION_12) {
		spdm_buffer_append_u32(&rsp_msg->buffer, context->local.capabilities.data_transfer_size);
		spdm_buffer_append_u32(&rsp_msg->buffer, context->local.capabilities.max_spdm_msg_size);
		LOG_INF("data_transfer_size=%x max_spdm_msg_size=%x",
				context->local.capabilities.data_transfer_size,
				context->local.capabilities.max_spdm_msg_size);
	}
	LOG_HEXDUMP_INF(rsp_msg->buffer.data, rsp_msg->buffer.write_ptr, "CAPABILITIES DATA:");
	spdm_context_update_m1m2_hash(context, req_msg, rsp_msg);

	spdm_buffer_resize(&context->message_a,
			context->message_a.size +
			req_msg->buffer.write_ptr + sizeof(req_msg->header) +
			rsp_msg->buffer.write_ptr + sizeof(rsp_msg->header));
	spdm_buffer_append_array(&context->message_a, &req_msg->header, sizeof(req_msg->header));
	spdm_buffer_append_array(&context->message_a, req_msg->buffer.data, req_msg->buffer.write_ptr);
	spdm_buffer_append_array(&context->message_a, &rsp_msg->header, sizeof(rsp_msg->header));
	spdm_buffer_append_array(&context->message_a, rsp_msg->buffer.data, rsp_msg->buffer.write_ptr);

	ret = 0;
cleanup:

	return ret;
}
