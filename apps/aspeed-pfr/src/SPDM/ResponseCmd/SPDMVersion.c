/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_handle_get_version(void *ctx, void *req, void *rsp)
{
	LOG_INF("Handle GET_VERSION");
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	int ret = -1;

	// Shall be 0x10 (V1.0)
	if (req_msg->header.spdm_version != SPDM_VERSION_10) {
		LOG_ERR("Unsupported header SPDM_VERSION %x", req_msg->header.spdm_version);
		rsp_msg->header.request_response_code = SPDM_RSP_ERROR;
		rsp_msg->header.param1 = SPDM_ERROR_CODE_MAJOR_VERSION_MISMATCH;
		ret = -1;
		goto cleanup;
	}

	// Shall be 0x10 (V1.0)
	rsp_msg->header.spdm_version = SPDM_VERSION_10;
	rsp_msg->header.request_response_code = SPDM_RSP_VERSION;
	rsp_msg->header.param1 = 0;
	rsp_msg->header.param2 = 0;

	spdm_buffer_init(&rsp_msg->buffer, 2 + 2 * context->local.version.version_number_entry_count);
	spdm_buffer_append_reserved(&rsp_msg->buffer, 1);
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.version.version_number_entry_count);
	for (uint8_t i=0; i < SPDM_MAX_VERSION && i < context->local.version.version_number_entry_count; ++i) {
		spdm_buffer_append_u16(&rsp_msg->buffer, context->local.version.version_number_entry[i]);
	}

	spdm_context_reset_m1m2_hash(context);
	spdm_context_update_m1m2_hash(context, req_msg, rsp_msg);
	
	spdm_buffer_release(&context->message_a);
	spdm_buffer_init(&context->message_a, 0);
	/* Construct transcript for challenge */
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
