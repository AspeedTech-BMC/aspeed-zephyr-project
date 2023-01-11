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
	int ret;

	if (req_msg->header.spdm_version != SPDM_VERSION) {
		LOG_ERR("Unsupported header SPDM_VERSION %x", req_msg->header.spdm_version);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_MAJOR_VERSION_MISMATCH;
		ret = -1;
		goto cleanup;
	}

	rsp_msg->header.request_response_code = SPDM_RSP_VERSION;
	rsp_msg->header.param1 = 0;
	rsp_msg->header.param2 = 0;

	spdm_buffer_init(&rsp_msg->buffer, 2 + 2 * context->local.version.version_number_entry_count);
	spdm_buffer_append_reserved(&rsp_msg->buffer, 1);
	spdm_buffer_append_u8(&rsp_msg->buffer, context->local.version.version_number_entry_count);
	for (uint8_t i=0; i < context->local.version.version_number_entry_count; ++i) {
		spdm_buffer_append_u16(&rsp_msg->buffer, context->local.version.version_number_entry[i]);
	}

	spdm_context_reset_m1m2_hash(context);
	spdm_context_update_m1m2_hash(context, req_msg, rsp_msg);
	
	ret = 0;

cleanup:

	return ret;
}
