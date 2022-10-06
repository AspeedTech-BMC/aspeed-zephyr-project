/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_crl.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_get_certificate(void *ctx, uint8_t slot_id)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	uint16_t offset = 0;
	uint16_t block_size = 0xF0;
	bool first_request = true;
	do {
		struct spdm_message req_msg, rsp_msg;

		req_msg.header.spdm_version = SPDM_VERSION;
		req_msg.header.request_response_code = SPDM_REQ_GET_CERTIFICATE;
		req_msg.header.param1 = slot_id & 0x0F;
		req_msg.header.param2 = 0;

		spdm_buffer_init(&req_msg.buffer, 4);
		spdm_buffer_append_u16(&req_msg.buffer, offset);
		spdm_buffer_append_u16(&req_msg.buffer, block_size);

		spdm_send_request(context, &req_msg, &rsp_msg);

		uint16_t portion_length, remainder_length;
		spdm_buffer_get_u16(&rsp_msg.buffer, &portion_length);
		spdm_buffer_get_u16(&rsp_msg.buffer, &remainder_length);

		if (first_request) {
			if (context->remote.certificate.certs[slot_id].data) {
				free(context->remote.certificate.certs[slot_id].data);
				context->remote.certificate.certs[slot_id].data = NULL;
			}
			// Allocate the certificate memory
			context->remote.certificate.certs[slot_id].size = portion_length + remainder_length;
			context->remote.certificate.certs[slot_id].data =
				(uint8_t *)malloc(portion_length + remainder_length);
			if (context->remote.certificate.certs[slot_id].data == NULL) {
				LOG_ERR("Failed to alloc memory size=%d", portion_length + remainder_length);
				return -1;
			}
			first_request = false;
		}
		spdm_buffer_get_array(&rsp_msg.buffer,
				context->remote.certificate.certs[slot_id].data + offset,
				portion_length);
		offset += portion_length;
	
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

		if (remainder_length == 0) {
			break;
		}
	} while (1);

	/* Load Root Certificate */
	mbedtls_x509_crt *ca_cert = &context->remote.certificate.root_ca;
	uint32_t flags;
	int ret;

	/* Verify the certificate */
	mbedtls_x509_crt remote_cert;
	mbedtls_x509_crt *cur = &remote_cert;
	mbedtls_x509_crt_init( &remote_cert );
	ret = mbedtls_x509_crt_parse_der(
			&remote_cert,
			context->remote.certificate.certs[slot_id].data + 4 + 48,
			context->remote.certificate.certs[slot_id].size - 4 - 48);
	if (ret < 0) {
		LOG_ERR("Failed to load remote certificate, ret=%x", -ret);
#if 1
		LOG_HEXDUMP_ERR(context->remote.certificate.certs[slot_id].data,
				context->remote.certificate.certs[slot_id].size,
				"Certificate:");
#else
		LOG_ERR("Certificate slot[%d] size=%d",
			slot_id,
			context->remote.certificate.certs[slot_id].size);
#endif
	}

	while (cur != NULL) {
		char *buf = malloc(CONFIG_LOG_STRDUP_MAX_STRING);
		int ret;
		ret = mbedtls_x509_crt_info(buf, CONFIG_LOG_STRDUP_MAX_STRING-1, "\r", cur);
		if (ret > 0) {
			buf[ret] = '\0';
			LOG_INF("Certificate info:\n%s", log_strdup(buf));
		}
		cur = cur->next;
		free(buf);
	}
	ret = mbedtls_x509_crt_verify(&remote_cert, ca_cert, NULL, NULL, &flags, NULL, NULL);
	if (ret < 0 || flags != 0) {
		LOG_ERR("Failed to verify certificate, erase it? ret=%x flags=%x", -ret, flags);
	} else {
		LOG_ERR("Certificate verified");
	}
	
	mbedtls_x509_crt_free(&remote_cert);

	return 0;
}
