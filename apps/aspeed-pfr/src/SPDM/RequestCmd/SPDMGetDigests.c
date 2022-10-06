/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_get_digests(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;

	req_msg.header.spdm_version = SPDM_VERSION;
	req_msg.header.request_response_code = SPDM_REQ_GET_DIGESTS;
	req_msg.header.param1 = 0;
	req_msg.header.param2 = 0;

	spdm_buffer_init(&req_msg.buffer, 0);

	spdm_send_request(context, &req_msg, &rsp_msg);
	/* Intel-PFR 3.0 supports SHA2-384 only */
	context->remote.certificate.slot_mask = rsp_msg.header.param2;

	LOG_HEXDUMP_INF(&rsp_msg.header, sizeof(rsp_msg.header), "DIGEST HEADER:");
	LOG_HEXDUMP_INF(rsp_msg.buffer.data, rsp_msg.buffer.size, "DIGEST:");

	
#if defined(SPDM_TRANSCRIPT)
	/* Construct transcript for challenge */
	spdm_buffer_resize(&context->message_b,
			context->message_b.size +
			req_msg.buffer.size + sizeof(req_msg.header) +
			rsp_msg.buffer.size + sizeof(rsp_msg.header));
	spdm_buffer_append_array(&context->message_b, &req_msg.header, sizeof(req_msg.header));
	spdm_buffer_append_array(&context->message_b, req_msg.buffer.data, req_msg.buffer.size);
	spdm_buffer_append_array(&context->message_b, &rsp_msg.header, sizeof(rsp_msg.header));
	spdm_buffer_append_array(&context->message_b, rsp_msg.buffer.data, rsp_msg.buffer.size);
#else
	spdm_context_update_m1m2_hash(context, &req_msg, &rsp_msg);
#endif

	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return 0;
}
