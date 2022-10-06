/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_get_version(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;
	int ret;

	req_msg.header.spdm_version = SPDM_VERSION;
	req_msg.header.request_response_code = SPDM_REQ_GET_VERSION;
	req_msg.header.param1 = 0;
	req_msg.header.param2 = 0;

	spdm_buffer_init(&req_msg.buffer, 0);

	ret = spdm_send_request(context, &req_msg, &rsp_msg);
	if (ret != 0) {
		LOG_ERR("GET_VERSION failed %x", ret);
		return -1;
	}

	spdm_buffer_get_reserved(&req_msg.buffer, 1);
	spdm_buffer_get_u8(&req_msg.buffer, &context->remote.version.version_number_entry_count);

	if (context->remote.version.version_number_entry_count > 0) {
		if (context->remote.version.version_number_entry != NULL) {
			free(context->remote.version.version_number_entry);
			context->remote.version.version_number_entry = NULL;
		}
		context->remote.version.version_number_entry =
			malloc(context->remote.version.version_number_entry_count * sizeof(uint16_t));
		for (size_t i = 0; i < context->remote.version.version_number_entry_count; ++i) {
			spdm_buffer_get_u16(&req_msg.buffer, &context->remote.version.version_number_entry[i]);
		}
	}

	LOG_HEXDUMP_INF(&rsp_msg.header, sizeof(rsp_msg.header), "VERSION HEADER:");
	LOG_HEXDUMP_INF(rsp_msg.buffer.data, rsp_msg.buffer.size, "VERSION DATA:");

#if defined(SPDM_TRANSCRIPT)
	/* Reset the buffer */
	spdm_buffer_release(&context->message_a);
	spdm_buffer_release(&context->message_b);
	spdm_buffer_release(&context->message_c);

	spdm_buffer_init(&context->message_a, 0);
	spdm_buffer_init(&context->message_b, 0);
	spdm_buffer_init(&context->message_c, 0);

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
	/* Reset the hash context */
	spdm_context_reset_m1m2_hash(context);
	spdm_context_update_m1m2_hash(context, &req_msg, &rsp_msg);
#endif


	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return 0;
}

