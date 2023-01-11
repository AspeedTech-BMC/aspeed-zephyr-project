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

	int ret;

	if (req_msg->header.spdm_version != SPDM_VERSION) {
		LOG_ERR("Unsupported header SPDM_VERSION %x", req_msg->header.spdm_version);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_MAJOR_VERSION_MISMATCH;
		ret = -1;
		goto cleanup;
	}
#if 0
	/* SPDM 1.1 */
	spdm_buffer_get_reserved(&req_msg->buffer, 1);
	spdm_buffer_get_u8(&req_msg->buffer, &context->remote.capabilities.ct_exponent);
	spdm_buffer_get_reserved(&req_msg->buffer, 2);
	spdm_buffer_get_u32(&req_msg->buffer, &context->remote.capabilities.flags);
	spdm_buffer_get_u32(&req_msg->buffer, &context->remote.capabilities.data_transfer_size);
	spdm_buffer_get_u32(&req_msg->buffer, &context->remote.capabilities.max_spdm_msg_size);
#endif

	/* Set the flags according to *_CAP: serializer */
	rsp_msg->header.request_response_code = SPDM_RSP_CAPABILITIES;
	rsp_msg->header.param1 = 0;
	rsp_msg->header.param2 = 0;

	spdm_buffer_init(&rsp_msg->buffer, 16);
	spdm_buffer_append_reserved(&rsp_msg->buffer, 1);
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.capabilities.ct_exponent);
	spdm_buffer_append_reserved(&rsp_msg->buffer, 2);
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.capabilities.flags);
#if 0
	/* SPDM 1.1 */
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.capabilities.data_transfer_size);
	spdm_buffer_append_u32(&rsp_msg->buffer, context->local.capabilities.max_spdm_msg_size);
#endif

	spdm_context_update_m1m2_hash(context, req_msg, rsp_msg);

	ret = 0;
cleanup:

	return ret;
}
