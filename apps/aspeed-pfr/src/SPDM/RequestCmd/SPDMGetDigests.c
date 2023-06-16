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
	int ret;

	req_msg.header.spdm_version = context->local.version.version_number_selected;
	req_msg.header.request_response_code = SPDM_REQ_GET_DIGESTS;
	req_msg.header.param1 = 0;
	req_msg.header.param2 = 0;

	spdm_buffer_init(&req_msg.buffer, 0);
	spdm_buffer_init(&rsp_msg.buffer, 0);

	ret = spdm_send_request(context, &req_msg, &rsp_msg);
	if (ret != 0) {
		LOG_ERR("GET_DIGEST failed %x", ret);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.spdm_version != req_msg.header.spdm_version) {
		LOG_ERR("Unsupported header SPDM_VERSION Req %02x Rsp %02x",
				req_msg.header.spdm_version, rsp_msg.header.spdm_version);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.request_response_code != SPDM_RSP_DIGESTS) {
		LOG_ERR("Expecting DIGESTS message but got %02x Param[%02x,%02x]",
				rsp_msg.header.request_response_code,
				rsp_msg.header.param1,
				rsp_msg.header.param2);
		ret = -1;
		goto cleanup;
	}

	/* Intel-PFR 3.0 supports SHA2-384 only */
	context->remote.certificate.slot_mask = 0;
	uint8_t slot_mask = rsp_msg.header.param2;
	uint8_t count = 0;
	for (uint8_t mask = 0x01; mask; mask <<= 1) {
		if (mask & slot_mask) {
			++count;
		}
	}

	if (rsp_msg.buffer.write_ptr != count*48) {
		LOG_ERR("DIGESTS response length incorrect len=%d expect=%d",
				rsp_msg.buffer.write_ptr, count*48);
		ret = -1;
		goto cleanup;
	}

	/* Store the digest of certificates */
	context->remote.certificate.slot_mask = slot_mask;
	for (uint8_t slot_id = 0x00; slot_id < 8; ++slot_id) {
		if (slot_mask & (1<<slot_id)) {
			spdm_buffer_get_array(&rsp_msg.buffer, 
					context->remote.certificate.certs[slot_id].digest, 48);
		}
	}
	ret = 0;

	LOG_HEXDUMP_INF(&rsp_msg.header, sizeof(rsp_msg.header), "DIGEST HEADER:");
	LOG_HEXDUMP_DBG(rsp_msg.buffer.data, rsp_msg.buffer.size, "DIGEST:");


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

cleanup:
	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return ret;
}
