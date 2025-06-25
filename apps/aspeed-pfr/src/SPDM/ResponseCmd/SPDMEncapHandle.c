/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMResponder.h"
#include "SPDM/ResponseCmd/SPDMResponseCmd.h"
#include "SPDM/SPDMSession.h"
#include "SPDM/SPDMKeyOperation.h"

#include <mbedtls/sha512.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <stdlib.h>

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

typedef enum {
	ENCAP_OP_GET_CERT_FIRST,
	ENCAP_OP_GET_CERT_CONT,
	ENCAP_OP_GET_CERT_DONE,
	ENCAP_OP_END
} ENCAP_OP_STATE;

typedef enum {
	ENCAP_GET_CERT_FAILED = -1,
	ENCAP_GET_CERT_CONT = 0,
	ENCAP_GET_CERT_VERIFY_DONE = 1
} ENCAP_GET_CERT_STATE;

static int verify_deliver_encap_rsp_body(struct spdm_context *context, struct spdm_message *req_msg, uint8_t *encap_rsp_code)
{
	struct spdm_message_header *encap_header;

	encap_header = (struct spdm_message_header *)req_msg->buffer.data;
	if (req_msg->buffer.write_ptr < 4) {
		LOG_ERR("Invalid encap rsp size (%d)", req_msg->buffer.write_ptr);
		return -1;
	}

	*encap_rsp_code = encap_header->request_response_code;

	return 0;
}

static int8_t get_next_cert_id(struct spdm_context *context, int8_t curr_id)
{
	int8_t slot_id;

	for (slot_id = curr_id+1; slot_id < 8; ++slot_id) {
		if (context->remote.certificate.slot_mask & (1<<slot_id))
			return slot_id;
	}

	return 0x7f;
}

static int build_encap_message(struct spdm_context *context, struct spdm_message *req_msg, struct spdm_message *rsp_msg, int op_code)
{
	rsp_msg->header.spdm_version = req_msg->header.spdm_version;
	rsp_msg->header.request_response_code = SPDM_RSP_ENCAP_RSP_ACK;
	rsp_msg->header.param1 = 0;
	rsp_msg->header.param2 = 0;

	if (op_code == 0) {
		spdm_buffer_init(&rsp_msg->buffer, 4);
		/* Add ACKRequestID */
		spdm_buffer_append_u8(&rsp_msg->buffer, req_msg->header.param1);
		/* Add Reserved bytes */
		spdm_buffer_append_reserved(&rsp_msg->buffer, 3);
	} else {
		/* Error case */
		spdm_buffer_init(&rsp_msg->buffer, 8);
		/* Add ACKRequestID */
		spdm_buffer_append_u8(&rsp_msg->buffer, req_msg->header.param1);
		/* Add Reserved bytes */
		spdm_buffer_append_reserved(&rsp_msg->buffer, 3);
		/* Add SPDM version */
		spdm_buffer_append_u8(&rsp_msg->buffer, req_msg->header.spdm_version);
		/* Add error code */
		spdm_buffer_append_u8(&rsp_msg->buffer, 0x7f);
		/*
		 * Add error code, ToDo : to insert corresponding error code
		 * for different error cases
		 */
		spdm_buffer_append_u8(&rsp_msg->buffer, 0x5);
		spdm_buffer_append_u8(&rsp_msg->buffer, 0x0);
	}

	return 0;
}

int spdm_encap_get_digests(struct spdm_context *context, struct spdm_message *rsp_msg)
{
	struct spdm_message_header encap_header;
	uint8_t slot_mask;
	uint8_t count = 0;

	spdm_buffer_get_array(&rsp_msg->buffer, &encap_header, 4);

	slot_mask = encap_header.param2;
	for (uint8_t mask = 0x01; mask; mask <<= 1) {
		if (mask & slot_mask)
			++count;
	}

	if (rsp_msg->buffer.write_ptr - sizeof(struct spdm_message_header) != count*48) {
		LOG_ERR("DIGESTS response length incorrect len=%d expect=%d",
				rsp_msg->buffer.write_ptr, count*48);
		return -1;
	}

	/* Store the digest of certificates */
	context->remote.certificate.slot_mask = slot_mask;
	for (uint8_t slot_id = 0x00; slot_id < 8; ++slot_id) {
		if (slot_mask & (1<<slot_id)) {
			spdm_buffer_get_array(&rsp_msg->buffer,
				context->remote.certificate.certs[slot_id].digest, 48);
		}
	}

	return 0;
}

int spdm_encap_get_certificate(struct spdm_context *context, struct spdm_message *req_msg,
		struct spdm_message *rsp_msg, bool first_request, uint8_t slot_id)
{
	static bool first_reply = true;
	static uint16_t offset;
	uint16_t block_size = 0xF0;
	int ret = 0;
	uint16_t portion_length = 0, remainder_length = 0xff;
	struct spdm_message_header encap_header;

	rsp_msg->header.spdm_version = req_msg->header.spdm_version;
	rsp_msg->header.request_response_code = SPDM_RSP_ENCAP_RSP_ACK;
	rsp_msg->header.param1 = req_msg->header.param1;
	rsp_msg->header.param2 = 1;

	if (first_request == false) {
		spdm_buffer_get_array(&req_msg->buffer, &encap_header, sizeof(encap_header));
		spdm_buffer_get_u16(&req_msg->buffer, &portion_length);
		spdm_buffer_get_u16(&req_msg->buffer, &remainder_length);

		/* Check the message length again */
		if (req_msg->buffer.write_ptr != portion_length + 4 + sizeof(encap_header)) {
			LOG_ERR("CERTIFICATE portion length incorrect");
			return ENCAP_GET_CERT_FAILED;
		}
	} else {
		offset = 0;
		first_reply = false;
	}

	if (remainder_length == 0) {
		/* Get the final part of the certificate */
		spdm_buffer_get_array(&req_msg->buffer,
				context->remote.certificate.certs[slot_id].data + offset,
				portion_length);

		LOG_INF("CERTIFICATE %d is received, to validate it, cert size = %x", slot_id,
			context->remote.certificate.certs[slot_id].size);
		/* Check DIGEST first */
		uint8_t hash[48];

		mbedtls_sha512(context->remote.certificate.certs[slot_id].data,
				context->remote.certificate.certs[slot_id].size,
				hash, 1);
		if (memcmp(hash, context->remote.certificate.certs[slot_id].digest, 48) != 0) {
			LOG_ERR("Certificate[%d] doesn't match with DIGEST", slot_id);
			LOG_HEXDUMP_ERR(hash, 48, "HASH:");
			LOG_HEXDUMP_ERR(context->remote.certificate.certs[slot_id].digest, 48,
					"DIGESTS:");
			build_encap_message(context, req_msg, rsp_msg, 1);
			return ENCAP_GET_CERT_FAILED;
		} else {
			mbedtls_x509_crt *ca_cert = spdm_get_root_certificate();
			uint32_t flags;

			/* Verify the certificate */
			mbedtls_x509_crt *remote_cert;
			size_t asn1_len, current_cert_len = 0;
			size_t cert_chain_len;
			uint8_t *cert_chain;
			uint8_t *tmp_ptr, *current_cert, *end;
			int32_t current_index = -1;

			remote_cert = &context->remote.certificate.certs[slot_id].chain;
			cert_chain_len = context->remote.certificate.certs[slot_id].size - 4 - 48;
			cert_chain = context->remote.certificate.certs[slot_id].data + 4 + 48;
			current_cert = cert_chain;
			end = cert_chain + cert_chain_len;
			mbedtls_x509_crt_free(remote_cert);
			mbedtls_x509_crt_init(remote_cert);
			while (true) {
				tmp_ptr = current_cert;
				if (current_cert >= end)
					break;

				ret = mbedtls_asn1_get_tag(
					&tmp_ptr, end, &asn1_len,
					MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
				if (ret != 0)
					break;

				current_cert_len = asn1_len + (tmp_ptr - current_cert);
				current_index++;

				if (current_index) {
					/*
					 * If there are more certificates,
					 * to verify it before inserting it
					 */
					ret = append_next_certificate(
						remote_cert,
						current_cert,
						current_cert_len);
					if (ret)
						break;
				} else {
					/* insert first certificate to remote_cert */
					ret = mbedtls_x509_crt_parse_der_nocopy(
						remote_cert, current_cert,
						current_cert_len);
					if (ret < 0)
						break;
				}

				current_cert = current_cert + current_cert_len;
			}
			if (ret == 0)
				ret = mbedtls_x509_crt_verify(remote_cert, ca_cert, NULL,
						NULL, &flags, NULL, NULL);
			if (ret < 0 || flags != 0) {
				LOG_ERR("Failed to verify Certificate[%d], ret=%x flags=%x",
					slot_id, -ret, flags);
				/* Drop the certificate */
				free(context->remote.certificate.certs[slot_id].data);
				context->remote.certificate.certs[slot_id].data = NULL;
				context->remote.certificate.certs[slot_id].size = 0;
				context->remote.certificate.slot_mask &= ~(1 << slot_id);
				mbedtls_x509_crt_free(remote_cert);
				build_encap_message(context, req_msg, rsp_msg, 1);
				return ENCAP_GET_CERT_FAILED;
			} else
				LOG_INF("Certificate[%d] verified", slot_id);

			return ENCAP_GET_CERT_VERIFY_DONE;
		}
	}
	spdm_buffer_init(&rsp_msg->buffer, 16);

	/* Add ACKRequestID */
	spdm_buffer_append_u8(&rsp_msg->buffer, req_msg->header.param1);
	/* Add Reserved bytes */
	spdm_buffer_append_reserved(&rsp_msg->buffer, 3);
	/* Add EncapsulatedRequest */
	spdm_buffer_append_u8(&rsp_msg->buffer, req_msg->header.spdm_version);
	spdm_buffer_append_u8(&rsp_msg->buffer, SPDM_REQ_GET_CERTIFICATE);
	spdm_buffer_append_u8(&rsp_msg->buffer, 0);
	spdm_buffer_append_u8(&rsp_msg->buffer, slot_id);
	spdm_buffer_append_u16(&rsp_msg->buffer, offset + portion_length);
	spdm_buffer_append_u16(&rsp_msg->buffer, block_size);

	if (first_reply) {
		if (context->remote.certificate.certs[slot_id].data) {
			free(context->remote.certificate.certs[slot_id].data);
			context->remote.certificate.certs[slot_id].data = NULL;
		}
		// Allocate the certificate memory
		context->remote.certificate.certs[slot_id].size =
			portion_length + remainder_length;
		context->remote.certificate.certs[slot_id].data =
			(uint8_t *)malloc(portion_length + remainder_length);
		if (context->remote.certificate.certs[slot_id].data == NULL) {
			LOG_ERR("Failed to alloc memory size = %d",
				portion_length + remainder_length);
			return ENCAP_GET_CERT_FAILED;
		}
		first_reply = false;
	}

	if (first_request == false) {
		spdm_buffer_get_array(&req_msg->buffer,
				context->remote.certificate.certs[slot_id].data + offset,
				portion_length);
		offset += portion_length;
	} else
		first_reply = true;

	return ENCAP_GET_CERT_CONT;
}

/*
 * Optimized session-based mutual authentication Flow:
 * When Responder sends the KEY_EXCHANGE_RSP, it also
 * set the MUTUAL AUTH request like GET_DIGEST in the
 * respond body.
 *             ┌───────────┐                 ┌───────────┐
 *             │ Requester │                 │ Responder │
 *             └─────┬─────┘                 └──────┬────┘
 *                  ┌┴┐                             │
 *                  └┬┴────────GET_VERSION────────►┌┴┐
 *                  ┌┴┐◄─────────VERSION───────────┴┬┘
 *                  └┬┴─────GET_CAPABILITIES──────►┌┴┐
 *                  ┌┴┐◄───────CAPABILITIES ───────┴┬┘
 *                  └┬┴───NEGOTIATE_ALGORITHMS────►┌┴┐
 *                  ┌┴┐◄────────ALGORITHMS─────────┴┬┘
 *                  └┬┴──────────GET_DIGESTS──────►┌┴┐
 *                  ┌┴┐◄─────────DIGESTS───────────┴┬┘
 *                  └┬┴──────GET_CERTIFICATES─────►┌┴┐
 *                  ┌┴┐◄────────CERTIFICATES───────┴┬┘
 *                  └┬┴────────KEY_EXCHANGE───────►┌┴┐
 *                  ┌┴┐◄KEY_EXCHANGE_RSP+GET_DIGEST┴┬┘
 * ┌─────────────┐--│ │-----------------------------│---+
 * │Session-Based│  │ │                             │   |
 * |MUTUAL AUTH  │  └┬┴─DELIVER_ENCAP_RSP (DIGEST)►┌┴┐  |
 * └─────────────/  ┌┴┐◄────ENCAP_RSP_ACK(CERT)────┴┬┘  |
 * |                └┬┴──DELIVER_ENCAP_RSP (CERT)─►┌┴┐  |
 * |                ┌┴┐◄──────ENCAP_RSP_ACK────────┴┬┘  |
 * +----------------│ │-----------------------------│---+
 *                  └┬┴───────────FINISH──────────►┌┴┐
 *                   |◄──────────FINISH_RSP────────┴┬┘
 *                   |                              |
 *
 */

int spdm_handle_deliver_encap_rsp(void *ctx, void *req, void *rsp, uint32_t *session_id)
{
	uint8_t encap_rsp_code;
	int encap_state = ENCAP_OP_END, ret = 0;
	static int8_t req_cert_slot_id = -1;

	LOG_INF("Enter Deliver Encap Response");
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;

	/*
	 * An Encap Response is like : 12 eb 00 00 12 02 00 00
	 * 4 bytes are SPDM header for Deliver Encap Response
	 * 4 bytes are real SPDM header for further operation
	 * to display header info to avoid tons messages.
	 */
	LOG_HEXDUMP_DBG(&req_msg->header, 4, "Deliver Encap Response Header");
	LOG_HEXDUMP_INF(req_msg->buffer.data, 4, "Deliver Encap Response");

	if (verify_deliver_encap_rsp_body(context, req_msg, &encap_rsp_code)) {
		LOG_ERR("Verify certificate chain failed");
		return -1;
	}

	switch (encap_rsp_code) {
	case SPDM_RSP_DIGESTS:
		if (spdm_encap_get_digests(context, req_msg))
			break;
		encap_state = ENCAP_OP_GET_CERT_FIRST;
		break;
	case SPDM_RSP_CERTIFICATE:
		ret = spdm_encap_get_certificate(context, req_msg, rsp_msg,
				false, req_cert_slot_id);
		if (ret == ENCAP_GET_CERT_VERIFY_DONE) {
			/*
			 * Previous certificate has been verified,
			 * to verify next certificate
			 */
			req_cert_slot_id = get_next_cert_id(context, req_cert_slot_id);
			if (req_cert_slot_id == 0x7f) {
				LOG_INF("All certificates are processed");
				encap_state = ENCAP_OP_GET_CERT_DONE;
			} else
				ret = spdm_encap_get_certificate(context, req_msg, rsp_msg,
					true, req_cert_slot_id);
		} else if (ret == ENCAP_GET_CERT_CONT)
			encap_state = ENCAP_OP_GET_CERT_CONT;
		break;
	}

	switch (encap_state) {
	case ENCAP_OP_GET_CERT_FIRST:
		req_cert_slot_id = get_next_cert_id(context, req_cert_slot_id);
		if (req_cert_slot_id == 0x7f) {
			LOG_ERR("No certificate");
			break;
		}
		ret = spdm_encap_get_certificate(context, req_msg, rsp_msg,
				true, req_cert_slot_id);
		break;
	case ENCAP_OP_GET_CERT_DONE:
		ret = build_encap_message(context, req_msg, rsp_msg, 0);
		break;
	case ENCAP_OP_GET_CERT_CONT:
	case ENCAP_OP_END:
		break;
	}
	/*
	 * An Encap Response ACK is like : 12 6b 00 01 00 00 00 00 12 82 00 02
	 * 4 bytes are SPDM header for Deliver Encap Response ACK
	 * 1 byte is ACKRequestID for identifying the communication session
	 * 3 bytes are reserved
	 * 4 bytes are real SPDM header for further operation
	 * The below debug code is displaying header info to avoid tons messages.
	 */
	LOG_HEXDUMP_DBG(&rsp_msg->header, 4, "Deliver Encap Response ACK Header");
	LOG_HEXDUMP_INF((uint8_t *)rsp_msg->buffer.data + 4, 4, "Deliver Encap Response ACK");

	return ret;
}
