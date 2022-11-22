/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_handle_get_certificate(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	int ret;

	uint8_t slot_id;
	uint16_t offset, length;
	slot_id = req_msg->header.param1; // Slot Id should be 0~7

	if (req_msg->header.spdm_version != SPDM_VERSION) {
		LOG_ERR("Unsupported header SPDM_VERSION %x", req_msg->header.spdm_version);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_MAJOR_VERSION_MISMATCH;
		ret = -1;
		goto cleanup;
	} else if (slot_id > 7 || !(context->local.certificate.slot_mask & (1<<slot_id))) {
		LOG_ERR("GET_CERTIFICATE Slot[%d] not exist. Slot_mask=%02x",
				slot_id, context->local.certificate.slot_mask);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
		ret = -1;
		goto cleanup;
	} else if (req_msg->buffer.write_ptr != 4) {
		LOG_ERR("GET_CERTIFICATE message length incorrect %d",
				req_msg->buffer.write_ptr + 4);
		rsp_msg->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
		ret = -1;
		goto cleanup;
	}

	spdm_buffer_get_u16(&req_msg->buffer, &offset);
	spdm_buffer_get_u16(&req_msg->buffer, &length);

	rsp_msg->header.request_response_code = SPDM_RSP_CERTIFICATE;
	rsp_msg->header.param1 = slot_id;
	rsp_msg->header.param2 = slot_id;

	/* Certificate Chain Data format:
	 * [0:1]   Length: Total length of the certificate chain in bytes, 
	 *                 including all fields in this table (Little endian.
	 * [2:3]   Reserved.
	 * [4:4+H] RootHash: Hash value of Root Certificate.
	 * [4+H:-] Certificate Chain data
	 * */

	/* TODO: Configurable maximum portion_length? */
	uint16_t portion_length = 0x100;
	uint16_t cert_size = context->local.certificate.certs[slot_id].size;

	if (cert_size > offset + portion_length) {
		spdm_buffer_init(&rsp_msg->buffer,
				2 + 2 + portion_length);
		spdm_buffer_append_u16(&rsp_msg->buffer, portion_length);
		spdm_buffer_append_u16(&rsp_msg->buffer, cert_size - (offset + portion_length));
	} else {
		portion_length = cert_size - offset;
		spdm_buffer_init(&rsp_msg->buffer,
				2 + 2 + portion_length);
		spdm_buffer_append_u16(&rsp_msg->buffer, portion_length);
		spdm_buffer_append_u16(&rsp_msg->buffer, 0);
	}

	spdm_buffer_append_array(&rsp_msg->buffer,
			context->local.certificate.certs[slot_id].data + offset,
			portion_length);

	spdm_context_update_m1m2_hash(context, req_msg, rsp_msg);
	ret = 0;

cleanup:
	return ret;
}
