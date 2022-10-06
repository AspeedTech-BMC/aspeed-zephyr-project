/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_handle_get_capabilities(void *ctx, void *req, void *rsp)
{
	LOG_INF("Handle GET_CAPABILITIES");
	struct spdm_context *context = (struct spdm_context *)ctx;

	/* Store requester's capabilities: deserializer */
	struct spdm_message *req_msg = (struct spdm_message *)req;
	spdm_buffer_get_reserved(&req_msg->buffer, 1);
	spdm_buffer_get_u8(&req_msg->buffer, &context->remote.capabilities.ct_exponent);
	spdm_buffer_get_reserved(&req_msg->buffer, 2);
	spdm_buffer_get_u32(&req_msg->buffer, &context->remote.capabilities.flags);
	spdm_buffer_get_u32(&req_msg->buffer, &context->remote.capabilities.data_transfer_size);
	spdm_buffer_get_u32(&req_msg->buffer, &context->remote.capabilities.max_spdm_msg_size);

	/* Set the flags according to *_CAP: serializer */
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	rsp_msg->header.request_response_code = SPDM_RSP_CAPABILITIES;
	rsp_msg->header.param1 = 0;
	rsp_msg->header.param2 = 0;

	spdm_buffer_init(&rsp_msg->buffer, 16);
	spdm_buffer_append_reserved(&rsp_msg->buffer, 1);
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.capabilities.ct_exponent);
	spdm_buffer_append_reserved(&rsp_msg->buffer, 2);
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.capabilities.flags);
	/* SPDM 1.1
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.capabilities.data_transfer_size);
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.capabilities.max_spdm_msg_size);
	*/
	spdm_context_update_m1m2_hash(context, req_msg, rsp_msg);

	return 0;
}
