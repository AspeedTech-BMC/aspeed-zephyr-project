/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <stdlib.h>

#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMMctpBinding.h"
#include "SPDM/SPDMKeyOperation.h"
#include "mbedtls/gcm.h"
#if defined(CONFIG_PFR_MCTP_I3C_5_0)
#include "mctp/mctp_i3c.h"
#endif

LOG_MODULE_REGISTER(spdm_mctp, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_mctp_send_recv(void *ctx, void *request_buf, void *response_buf)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_mctp_connection_data *conn =
		(struct spdm_mctp_connection_data *)context->connection_data;
	struct spdm_message *req_msg = (struct spdm_message *)request_buf;
	struct spdm_message *rsp_msg = (struct spdm_message *)response_buf;
	int ret;

	memset(conn->request_buf, 0, sizeof(conn->request_buf));

	conn->request_buf[0] = 0x05;
	memcpy(conn->request_buf + 1, &req_msg->header, sizeof(req_msg->header));
	memcpy(conn->request_buf + 1 + sizeof(req_msg->header), req_msg->buffer.data, req_msg->buffer.write_ptr);

	LOG_HEXDUMP_DBG(conn->request_buf, 1 + sizeof(req_msg->header) + req_msg->buffer.write_ptr, "MCTP REQ:");

	ret = mctp_interface_issue_request(
			&conn->mctp_inst->mctp_wrapper.mctp_interface,
			&conn->mctp_inst->mctp_cmd_channel,
			conn->dst_addr, conn->dst_eid,
			conn->request_buf, 1 + sizeof(req_msg->header) + req_msg->buffer.write_ptr,
			conn->request_buf, sizeof(conn->request_buf),
			5000
			);
	if (ret == 0) {
		// SPDM Header
		memcpy(&rsp_msg->header, conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.data + 1,
				sizeof(rsp_msg->header));

		// SPDM Payload
		spdm_buffer_init(&rsp_msg->buffer,
				conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.length - 1 - 4);
		spdm_buffer_append_array(&rsp_msg->buffer,
				conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.data + 1 + 4,
				conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.length - 1 - 4);
		LOG_HEXDUMP_DBG(rsp_msg->buffer.data, rsp_msg->buffer.write_ptr, "MCTP BUF SEND_RECV:");
		LOG_HEXDUMP_DBG(conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.data,
				conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.length,
				"MCTP RAW SEND_RECV:");
	} else {
		LOG_ERR("mctp_interface_issue_request ret=%x", ret);
	}

	return ret;
}

int spdm_mctp_recv(void *ctx, void *buffer, size_t *buffer_size)
{
	*buffer_size = 0;
	return 0;
}

#if defined(CONFIG_PFR_MCTP_I3C)
extern mctp * mctp_i3c_bmc_inst;
#endif

bool spdm_mctp_init_req(void *ctx, SPDM_MEDIUM medium, uint8_t bus, uint8_t dst_sa, uint8_t dst_eid)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_mctp_connection_data *conn;
	mctp *mctp_inst = NULL;

	switch (medium) {
	case SPDM_MEDIUM_SMBUS:
		mctp_inst = find_mctp_by_smbus(bus);
		break;
#if defined(CONFIG_PFR_MCTP_I3C)
	case SPDM_MEDIUM_I3C:
#if defined(CONFIG_PFR_MCTP_I3C_5_0)
		mctp_inst = mctp_i3c_target_get_by_bus(bus);
#else
		mctp_inst = mctp_i3c_bmc_inst;
#endif
		break;
#endif
	default:
		LOG_ERR("Unsupported Binding Spec 0x%02x", medium);
		return false;
	}

	if (mctp_inst != NULL) {
		conn = malloc(sizeof(struct spdm_mctp_connection_data));
		if (conn == NULL) {
			LOG_ERR("can't allocate for connection data (%d)", sizeof(struct spdm_mctp_connection_data));
			return false;
		}
		conn->mctp_inst = mctp_inst;
		conn->dst_addr = dst_sa;
		conn->dst_eid = dst_eid;
		conn->medium = medium;
		conn->bus = bus;
		context->connection_data = conn;
		context->send_recv = spdm_mctp_send_recv;
		context->send_recv_enc = spdm_mctp_send_recv_enc;
	}

	return mctp_inst != NULL;
}

void spdm_mctp_release_req(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_mctp_connection_data *conn = context->connection_data;

	free(conn);
}

#if defined(CONFIG_SECURE_CONNECTION_RESPONDER) || defined(CONFIG_SECURE_CONNECTION_REQUESTER)
int decrypt_secure_content(void *spdm_ctx, void *buffer, size_t *length, uint32_t *session_id)
{
	struct spdm_session_context *session;
	uint8_t *ptr = (uint8_t *)buffer, *a_data, *tag;
	mbedtls_gcm_context ctx;
	uint32_t key_size;
	uint16_t enc_msg_len;
	int ret;
	uint8_t *data_out = NULL;
	uint8_t salt[12];
	uint16_t sequence_num_in_header = 0;
	size_t secure_header_size;
	struct spdm_context *context = spdm_ctx;

	LOG_DBG("Incoming encrypted SPDM request");
	LOG_HEXDUMP_DBG(buffer, *length, "SPDM Data");

	if ((session_id == NULL) || (context == NULL)) {
		LOG_ERR("Invalid argument");
		return -1;
	}

	data_out = (uint8_t *)malloc(*length);
	if (data_out == NULL) {
		LOG_ERR("Failed to allocate memory (%d)", *length);
		return -1;
	}

	/*
	 * Decrypt MCTP buffer
	 * encrypted buffer is like : 06 03 01 ff ff 02 00 22 00 4e 02 92 b3 55 69 09 ...
	 * MCTP message type : 1 byte
	 * below content follows definition in the DSP0277 4.1 Secured Message format
	 * or Intel 814910 Section 6.5.8
	 * Session ID : 4 bytes
	 * Sequence number : 2 Bytes
	 * Length : 2 Bytes
	 * encrypted data
	 */
	/* Get MCTP message type */
	if ((*ptr & 0x7f) != MCTP_BASE_PROTOCOL_MSG_TYPE_SECURE) {
		LOG_ERR("Invalid type [%x]", *ptr);
		free(data_out);
		return -1;
	}
	ptr++;
	a_data = ptr;

	/* Get Session ID */
	memcpy(session_id, ptr, sizeof(uint32_t));
	ptr += sizeof(uint32_t);
	session = spdm_session_get(*session_id);
	if (session == NULL) {
		LOG_ERR("Failed to find session [%x]", *session_id);
		free(data_out);
		return -1;
	}
	LOG_DBG("Session id [%x]", *session_id);
	mbedtls_gcm_init(&ctx);
	memset(salt, 0, sizeof(salt));

	/* Get Sequence number */
	memcpy(&sequence_num_in_header, ptr, 2);
	ptr += 2;
	/* Get Secured data length */
	memcpy(&enc_msg_len, ptr, sizeof(uint16_t));
	ptr += 2;
	enc_msg_len -= 16; // tag size is 16 and tag is not included in data_in
	// From the Spec. 814910
	// The IV used in each AES-GCM encryption is generated by XORing the base IV
	// with the sequence number of the message.
	if (session->session_type == SPDM_RESPONSE_MODE) {
		key_size = sizeof(session->encryption_key_req) * 8;
		ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
				session->encryption_key_req, key_size);
		if (ret != 0) {
			LOG_ERR("mbedtls_gcm_setkey failed, %x", ret);
			free(data_out);
			return -1;
		}
		memcpy(salt, session->encryption_salt_req,
			sizeof(session->encryption_salt_req));
		*(uint64_t *)salt = *(uint64_t *)salt ^ session->sequence_number_req;
		session->sequence_number_req++;
		if (session->sequence_number_req >= MAX_SESSION_REKEY_COUNT)
			spdm_update_key(context, session, SPDM_REQUEST_MODE);
	} else {
		key_size = sizeof(session->encryption_key_rsp) * 8;
		ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
				session->encryption_key_rsp, key_size);
		if (ret != 0) {
			LOG_ERR("mbedtls_gcm_setkey failed, %x", ret);
			free(data_out);
			return -1;
		}
		memcpy(salt, session->encryption_salt_rsp,
			sizeof(session->encryption_salt_rsp));
		*(uint64_t *)salt = *(uint64_t *)salt ^ session->sequence_number_rsp;
		session->sequence_number_rsp++;
		if (session->sequence_number_rsp >= MAX_SESSION_REKEY_COUNT)
			spdm_update_key(context, session, SPDM_RESPONSE_MODE);
	}

	/* Session id + sequence number + secured data length */
	secure_header_size = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t);
	tag = a_data + secure_header_size + enc_msg_len;

	LOG_DBG("Encrypted data length = %d", enc_msg_len);
	ret = mbedtls_gcm_auth_decrypt(&ctx, (uint32_t)enc_msg_len,
					salt, (uint32_t)sizeof(salt),
					a_data, (uint32_t)secure_header_size,
					tag, (uint32_t)16,
					ptr, data_out);
	mbedtls_gcm_free(&ctx);
	if (ret != 0) {
		free(data_out);
		LOG_ERR("Failed to decrypt message, ret = %x", -ret);
		return -1;
	}
	SPDM_DBG_HEXDUMP(data_out, enc_msg_len, "Decrypted data");

	memcpy(length, data_out, sizeof(uint16_t));
	LOG_DBG("Length = %x", *length);
	memcpy(buffer, &data_out[2], *length);
	SPDM_DBG_HEXDUMP(buffer, *length, "Buffer");
	free(data_out);

	session->last_access_time = k_uptime_get();

	return 0;
}

int encrypt_secure_content(void *spdm_ctx, uint8_t *rsp_hdr,
		uint8_t *rsp_body, size_t rsp_body_len, void *buffer,
		size_t *length, uint32_t *session_id)
{
	struct spdm_context *context = spdm_ctx;
	struct spdm_session_context *session;
	struct spdm_message_header *hdr;
	uint8_t *ptr = (uint8_t *)buffer, *a_data, *tag, *ptr2;
	mbedtls_gcm_context ctx;
	uint32_t key_size;
	int ret;
	uint8_t salt[12], session_type;
	uint32_t random_count = 0;
	size_t msg_len = 0, total_len, secure_header_size, tag_size = 16;
	bool to_release_session = false, isSPDM = false;

	if (context) {
		session = spdm_session_get(*session_id);
		if (session == NULL) {
			LOG_WRN("Failed to find session [%x]", *session_id);
			return -1;
		}
		LOG_DBG("Session id [%x]", *session_id);

		hdr = (struct spdm_message_header *)rsp_hdr;
		// If responder header is presented, it means this is an SPDM control packet
		if (hdr) {
			isSPDM = true;
			if (hdr->request_response_code == SPDM_RSP_END_SESSION_ACK)
				to_release_session = true;
			//SPDM msg type + SPDM header size
			msg_len = 1 + sizeof(struct spdm_message_header);
		}

		// Total length field + response data length or app data length
		msg_len += sizeof(uint16_t) + rsp_body_len;
		session_type = spdm_isCapabilitiesEnabled(context, SPDM_ENCRYPT_CAP); //enc_mac
		if (session_type) {
			context->random_callback(context, (uint8_t *)&random_count,
						sizeof(random_count));
			random_count = random_count%SPDM_MAX_RAND_COUNT + 1;
			//add random data length
			msg_len += random_count;
		}

		// Session id + sequence number + secured data length
		secure_header_size = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t);
		total_len = secure_header_size + msg_len + tag_size;

		uint8_t *plain_text = malloc(msg_len);

		ptr2 = plain_text;
		if (plain_text == NULL) {
			LOG_ERR("Failed to allocate memory for encrypted data (%d)", msg_len);
			return -1;
		}

		if (isSPDM) {
			*(uint16_t *)ptr2 = sizeof(struct spdm_message_header) + rsp_body_len + 1;
			ptr2 += sizeof(uint16_t);
			*ptr2 = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
			ptr2++;
			memcpy(ptr2, (uint8_t *)hdr, sizeof(struct spdm_message_header));
			ptr2 += sizeof(struct spdm_message_header);
			if (rsp_body_len) {
				memcpy(ptr2, (uint8_t *)rsp_body, rsp_body_len);
				ptr2 += rsp_body_len;
			}
		} else {
			*(uint16_t *)ptr2 = rsp_body_len;
			ptr2 += sizeof(uint16_t);
			memcpy(ptr2, (uint8_t *)rsp_body, rsp_body_len);
			ptr2 += rsp_body_len;
		}

		if (session_type)
			context->random_callback(context, ptr2, random_count);

		memset(salt, 0, sizeof(salt));
		mbedtls_gcm_init(&ctx);
		/* Add message type */
		*ptr = MCTP_BASE_PROTOCOL_MSG_TYPE_SECURE | 0x80;
		ptr++;
		a_data = ptr;
		/* Add session id */
		memcpy(ptr, session_id, sizeof(uint32_t));
		ptr += 4;
		/* Add sequence number */
		// from the Spec. 814910
		// The IV used in each AES-GCM encryption is generated by XORing the base IV
		// with the sequence number of the message.
		if (session->session_type == SPDM_RESPONSE_MODE) {
			memcpy(salt, session->encryption_salt_rsp,
				sizeof(session->encryption_salt_rsp));
			memcpy(ptr, &session->sequence_number_rsp, sizeof(uint16_t));
			*(uint64_t *)salt = *(uint64_t *)salt ^ session->sequence_number_rsp;
			session->sequence_number_rsp++;
			key_size = sizeof(session->encryption_key_rsp) * 8;
			ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
				session->encryption_key_rsp, key_size);
			if (ret != 0) {
				LOG_ERR("mbedtls_gcm_setkey failed, %x", ret);
				free(plain_text);
				return -1;
			}
			if (session->sequence_number_rsp >= MAX_SESSION_REKEY_COUNT)
				spdm_update_key(context, session, SPDM_RESPONSE_MODE);
		} else {
			memcpy(salt, session->encryption_salt_req,
				sizeof(session->encryption_salt_req));
			memcpy(ptr, &session->sequence_number_req, sizeof(uint16_t));
			*(uint64_t *)salt = *(uint64_t *)salt ^ session->sequence_number_req;
			session->sequence_number_req++;
			key_size = sizeof(session->encryption_key_req) * 8;
			ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
				session->encryption_key_req, key_size);
			if (ret != 0) {
				LOG_ERR("mbedtls_gcm_setkey failed, %x", ret);
				free(plain_text);
				return -1;
			}
			if (session->sequence_number_req >= MAX_SESSION_REKEY_COUNT)
				spdm_update_key(context, session, SPDM_REQUEST_MODE);
		}
		ptr += 2;
		/* Add secured data length */
		*(uint16_t *)ptr = msg_len + tag_size;
		ptr += 2;
		tag = ptr + msg_len;

		ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, (uint32_t)msg_len,
					salt, (uint32_t)sizeof(salt),
					a_data, (uint32_t)secure_header_size,
					plain_text, ptr,
					(uint32_t)16, tag);
		mbedtls_gcm_free(&ctx);
		*length = total_len + 1;
		SPDM_DBG_HEXDUMP(plain_text, msg_len, "Send buffer");

		if (to_release_session)
			spdm_session_release(session);
		else
			session->last_access_time = k_uptime_get();
		free(plain_text);
	}

	return 0;
}

int encrypt_spdm_content(struct spdm_context *context, struct spdm_message *spdm_msg, void *buffer, size_t *length, uint32_t *session_id)
{
	uint32_t status;

	status = encrypt_secure_content(context, (uint8_t *)&spdm_msg->header,
			(uint8_t *)spdm_msg->buffer.data, spdm_msg->buffer.write_ptr,
			buffer, length, session_id);

	return status;
}

int spdm_mctp_send_recv_enc(void *ctx, void *request_buf, void *response_buf, uint32_t session_id)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_mctp_connection_data *conn =
		(struct spdm_mctp_connection_data *)context->connection_data;
	struct spdm_message *req_msg = (struct spdm_message *)request_buf;
	struct spdm_message *rsp_msg = (struct spdm_message *)response_buf;
	int ret;
	size_t len;

	if (req_msg == NULL || rsp_msg == NULL) {
		LOG_ERR("Invalid arguments %p, %p", req_msg, rsp_msg);
		return -1;
	}
	memset(conn->request_buf, 0, sizeof(conn->request_buf));

	if (encrypt_spdm_content(context, req_msg, conn->request_buf, &len, &session_id)) {
		LOG_ERR("Encrypt spdm data failed");
		return -1;
	}
	ret = mctp_interface_issue_request(
			&conn->mctp_inst->mctp_wrapper.mctp_interface,
			&conn->mctp_inst->mctp_cmd_channel,
			conn->dst_addr, conn->dst_eid,
			conn->request_buf, len,
			conn->request_buf, sizeof(conn->request_buf),
			5000
			);

	if (ret == 0) {
		if (decrypt_secure_content(context,
			conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.data,
			&conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.length,
			&session_id)) {
			LOG_ERR("Decrypt spdm data failed");
			return -1;
		}

		memcpy(&rsp_msg->header,
			conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.data + 1,
			sizeof(rsp_msg->header));

		// SPDM Payload
		spdm_buffer_init(&rsp_msg->buffer,
			conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.length - 1 - 4);
		spdm_buffer_append_array(&rsp_msg->buffer,
			conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.data + 1 + 4,
			conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.length - 1 - 4);

		LOG_HEXDUMP_DBG(conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.data,
			conn->mctp_inst->mctp_wrapper.mctp_interface.req_buffer.length,
			"MCTP RAW SEND_RECV:");
	} else {
		LOG_ERR("mctp_interface_issue_request ret=%x", ret);
	}

	return 0;
}

#else
int decrypt_secure_content(void *context, void *buffer, size_t *length, uint32_t *session_id)
{
	LOG_ERR("Code should not go through this path");
	return MCTP_BASE_PROTOCOL_UNSUPPORTED_OPERATION;
}

int encrypt_secure_content(void *context, uint8_t *rsp_hdr,
		uint8_t *rsp_body, size_t rsp_body_len, void *buffer, size_t *length, uint32_t *session_id)
{
	LOG_ERR("Code should not go through this path");
	return MCTP_BASE_PROTOCOL_UNSUPPORTED_OPERATION;
}

int encrypt_spdm_content(struct spdm_context *context, struct spdm_message *spdm_msg, void *buffer, size_t *length, uint32_t *session_id)
{
	LOG_ERR("Code should not go through this path");
	return -1;
}

int spdm_mctp_send_recv_enc(void *ctx, void *request_buf, void *response_buf, uint32_t session_id)
{
	LOG_ERR("Code should not go through this path");
	return -1;
}
#endif

