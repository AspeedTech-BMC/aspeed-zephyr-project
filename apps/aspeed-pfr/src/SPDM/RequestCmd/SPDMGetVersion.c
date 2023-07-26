/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_get_version(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;
	int ret;

	// Fixed to SPMD_10 for GET_VERSION HANDSHAKING
	req_msg.header.spdm_version = SPDM_VERSION_10;
	req_msg.header.request_response_code = SPDM_REQ_GET_VERSION;
	req_msg.header.param1 = 0;
	req_msg.header.param2 = 0;

	spdm_buffer_init(&req_msg.buffer, 0);
	spdm_buffer_init(&rsp_msg.buffer, 0);

	ret = spdm_send_request(context, &req_msg, &rsp_msg);
	if (ret != 0) {
		LOG_ERR("GET_VERSION failed %x", ret);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.spdm_version != SPDM_VERSION_10) {
		LOG_ERR("Unsupported header SPDM_VERSION %x", rsp_msg.header.spdm_version);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.request_response_code != SPDM_RSP_VERSION) {
		LOG_ERR("Expecting VERSION message but got %02x Param[%02x,%02x]",
				rsp_msg.header.request_response_code,
				rsp_msg.header.param1,
				rsp_msg.header.param2);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.buffer.write_ptr < 4 || (rsp_msg.buffer.write_ptr % 2 != 0)) {
		LOG_ERR("VERSION message length incorrect");
		ret = -1;
		goto cleanup;
	}

	spdm_buffer_get_reserved(&rsp_msg.buffer, 1);
	uint8_t count = 0;
	spdm_buffer_get_u8(&rsp_msg.buffer, &count);

	if (count > 0 && count < SPDM_MAX_VERSION) {
		context->remote.version.version_number_entry_count = 0;
		for (size_t i = 0; i < count; ++i) {
			uint16_t version = 0;
			//spdm_buffer_get_u16(&rsp_msg.buffer, &context->remote.version.version_number_entry[i]);
			spdm_buffer_get_u16(&rsp_msg.buffer, &version);
			// TODO: Prepare for SPDM 1.1 1.2
			context->remote.version.version_number_entry[i] = version;
			context->remote.version.version_number_entry_count = 1;

			version >>= 8;
			if (version > context->remote.version.version_number_selected) {
				context->local.version.version_number_selected = version;
				context->remote.version.version_number_selected = version;
			}
		}
		if (context->remote.version.version_number_entry_count == 0) {
			LOG_ERR("No supported version found");
			ret = -1;
			goto cleanup;
		}
	} else {
		LOG_ERR("Version Number Entry Count is 0");
		ret = -1;
		goto cleanup;
	}

	LOG_INF("Selected SPDM Version: %02x", context->local.version.version_number_selected);

	spdm_buffer_release(&context->message_a);
	spdm_buffer_init(&context->message_a, 0);
	/* Construct transcript for challenge */
	spdm_buffer_resize(&context->message_a,
			context->message_a.size +
			req_msg.buffer.size + sizeof(req_msg.header) +
			rsp_msg.buffer.size + sizeof(rsp_msg.header));
	spdm_buffer_append_array(&context->message_a, &req_msg.header, sizeof(req_msg.header));
	spdm_buffer_append_array(&context->message_a, req_msg.buffer.data, req_msg.buffer.write_ptr);
	spdm_buffer_append_array(&context->message_a, &rsp_msg.header, sizeof(rsp_msg.header));
	spdm_buffer_append_array(&context->message_a, rsp_msg.buffer.data, rsp_msg.buffer.write_ptr);

#if defined(SPDM_TRANSCRIPT)
	/* Reset the buffer */
	spdm_buffer_release(&context->message_b);
	spdm_buffer_release(&context->message_c);

	spdm_buffer_init(&context->message_b, 0);
	spdm_buffer_init(&context->message_c, 0);

#else
	/* Reset the hash context */
	spdm_context_reset_m1m2_hash(context);
	spdm_context_update_m1m2_hash(context, &req_msg, &rsp_msg);
#endif
	ret = 0;

cleanup:
	if (ret < 0) {
		LOG_HEXDUMP_ERR(&rsp_msg.header, sizeof(rsp_msg.header), "VERSION HEADER:");
		LOG_HEXDUMP_ERR(rsp_msg.buffer.data, rsp_msg.buffer.size, "VERSION DATA:");
	}

	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return ret;
}

