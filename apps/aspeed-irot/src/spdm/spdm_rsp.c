/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <assert.h>
#include <zephyr/kernel.h>

#include <spdm_rsp.h>

#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(spdm_rsp, LOG_LEVEL_INF);

#include <industry_standard/spdm.h>
#include <library/spdm_common_lib.h>
#include <library/spdm_responder_lib.h>
#include <library/spdm_transport_mctp_lib.h>
#include <hal/library/memlib.h>
#include <cptra/cptra_api.h>
#include <cert.h>

#define NDEBUG
#define LIBSPDM_MAX_SPDM_MSG_SIZE 4096
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE (1024 - 0x100)
#define LIBSPDM_SENDER_BUFFER_SIZE LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE
#define LIBSPDM_RECEIVER_BUFFER_SIZE LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE
#define LIBSPDM_ASSERT(x) assert(x)

struct app_context_t {
	void *mctp_p;
	mctp_ext_params ext_params;

	void *recv_buffer;
	size_t recv_buffer_size;
};

static bool m_send_receive_buffer_acquired = false;
static uint8_t m_send_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
static libspdm_return_t spdm_device_acquire_sender_buffer (
	void *context, void **msg_buf_ptr)
{
	LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
	*msg_buf_ptr = m_send_receive_buffer;
	libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
	m_send_receive_buffer_acquired = true;
	return LIBSPDM_STATUS_SUCCESS;
}

static void spdm_device_release_sender_buffer (
	void *context, const void *msg_buf_ptr)
{
	LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
	LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
	m_send_receive_buffer_acquired = false;
	return;
}

static libspdm_return_t spdm_device_acquire_receiver_buffer (
	void *context, void **msg_buf_ptr)
{
	LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
	*msg_buf_ptr = m_send_receive_buffer;
	libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
	m_send_receive_buffer_acquired = true;
	return LIBSPDM_STATUS_SUCCESS;
}

static void spdm_device_release_receiver_buffer (
	void *context, const void *msg_buf_ptr)
{
	LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
	LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
	m_send_receive_buffer_acquired = false;
	return;
}

static libspdm_return_t spdm_device_send_message(void *spdm_context,
					  size_t message_size,
					  const void *message,
					  uint64_t timeout)
{
	LOG_DBG("spdm_device_send_message ctx=%p buffer=%p", spdm_context, message);
	LOG_HEXDUMP_DBG(message, message_size, "SSP >> BMC");


	struct app_context_t *app_context = NULL;
	size_t mctp_p_size = sizeof(struct app_context_t);
	libspdm_data_parameter_t parameter;

	libspdm_zero_mem(&parameter, sizeof(parameter));
	libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter, &app_context, &mctp_p_size);
	

	mctp_send_msg(app_context->mctp_p, (uint8_t *)message, (uint16_t)message_size, app_context->ext_params);

	return 0;
}

static libspdm_return_t spdm_device_receive_message(void *spdm_context, size_t *message_size, void **message, uint64_t timeout)
{
	/* For testing, we can directly copy the request message to the receive buffer. */
	struct app_context_t *app_context = NULL;
	size_t mctp_p_size = sizeof(struct app_context_t);
	libspdm_data_parameter_t parameter;

	libspdm_zero_mem(&parameter, sizeof(parameter));
	libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter, &app_context, &mctp_p_size);

	if (app_context->recv_buffer != NULL && app_context->recv_buffer_size > 0) {
		*message_size = app_context->recv_buffer_size;
		memcpy(*message, app_context->recv_buffer, app_context->recv_buffer_size);

		free(app_context->recv_buffer);
		app_context->recv_buffer = NULL;
		app_context->recv_buffer_size = 0;
	}
	return 0;
}

void spdm_connection_negotiate_callback(void *spdm_context)
{
#if 0
    /* Certificate info */
    LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
    LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
    LIBSPDM_DATA_PEER_PUBLIC_KEY,
    LIBSPDM_DATA_LOCAL_PUBLIC_KEY,
    LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK,
    LIBSPDM_DATA_LOCAL_KEY_PAIR_ID,
    LIBSPDM_DATA_LOCAL_CERT_INFO,
    LIBSPDM_DATA_LOCAL_KEY_USAGE_BIT_MASK,

    LIBSPDM_DATA_BASIC_MUT_AUTH_REQUESTED,
    LIBSPDM_DATA_MUT_AUTH_REQUESTED,
    LIBSPDM_DATA_HEARTBEAT_PERIOD,

    /* Negotiated result */
    LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,
    LIBSPDM_DATA_PEER_SLOT_MASK,
    LIBSPDM_DATA_PEER_PROVISIONED_SLOT_MASK = LIBSPDM_DATA_PEER_SLOT_MASK,
    LIBSPDM_DATA_PEER_SUPPORTED_SLOT_MASK,
    LIBSPDM_DATA_PEER_TOTAL_DIGEST_BUFFER,
    LIBSPDM_DATA_PEER_KEY_PAIR_ID,
    LIBSPDM_DATA_PEER_CERT_INFO,
    LIBSPDM_DATA_PEER_KEY_USAGE_BIT_MASK,
#endif

}

void spdm_server_connection_state_callback(
    void *spdm_context, libspdm_connection_state_t connection_state)
{
	// Show log for connection state change
	switch (connection_state) {
		case LIBSPDM_CONNECTION_STATE_NOT_STARTED:
			LOG_INF("Connection state: NOT_STARTED");
			break;
		case LIBSPDM_CONNECTION_STATE_AFTER_VERSION:
			LOG_INF("Connection state: AFTER_VERSION");
			break;
		case LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES:
			LOG_INF("Connection state: AFTER_CAPABILITIES");
			break;
		case LIBSPDM_CONNECTION_STATE_NEGOTIATED:
			LOG_INF("Connection state: NEGOTIATED");
			spdm_connection_negotiate_callback(spdm_context);
			break;
		case LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS:
			LOG_INF("Connection state: AFTER_DIGESTS");
			break;
		case LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE:
			LOG_INF("Connection state: AFTER_CERTIFICATE");
			break;
		case LIBSPDM_CONNECTION_STATE_AUTHENTICATED:
			LOG_INF("Connection state: AUTHENTICATED");
			break;
		default:
			LOG_INF("Connection state: UNKNOWN (%d)", connection_state);
			break;
	}

}

void spdm_server_session_state_callback(void *spdm_context,
                                        uint32_t session_id,
                                        libspdm_session_state_t session_state)
{
	/* Show log for session state change */
	switch (session_state) {
		case LIBSPDM_SESSION_STATE_NOT_STARTED:
			LOG_INF("Session state: NOT_STARTED");
			break;
		case LIBSPDM_SESSION_STATE_HANDSHAKING:
			LOG_INF("Session state: HANDSHAKING");
			break;
		case LIBSPDM_SESSION_STATE_ESTABLISHED:
			LOG_INF("Session state: ESTABLISHED");
			break;
		default:
			LOG_INF("Session state: UNKNOWN (%d)", session_state);
			break;
	}
}

static void *spdm_server_init(void *app_context)
{
	void *spdm_ctx = (void *)malloc(libspdm_get_context_size());
	bool ret = false;
	
	LOG_INF("SPDM context size=%d ptr=%p", libspdm_get_context_size(), spdm_ctx);
	assert(spdm_ctx != NULL);

	libspdm_init_context(spdm_ctx);
	
	libspdm_register_device_io_func (
		spdm_ctx,
		spdm_device_send_message,
		spdm_device_receive_message);

	libspdm_register_device_buffer_func (
		spdm_ctx,
		LIBSPDM_SENDER_BUFFER_SIZE, // defined by the Integrator
		LIBSPDM_RECEIVER_BUFFER_SIZE, // defined by the Integrator
		spdm_device_acquire_sender_buffer,
		spdm_device_release_sender_buffer,
		spdm_device_acquire_receiver_buffer,
		spdm_device_release_receiver_buffer);

	libspdm_register_transport_layer_func (
		spdm_ctx,
		LIBSPDM_MAX_SPDM_MSG_SIZE, // defined by the Integrator
		LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
		LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
		libspdm_transport_mctp_encode_message,
		libspdm_transport_mctp_decode_message);

	LOG_INF("m_send_receive_buffer=%p", (void *)m_send_receive_buffer);

	size_t scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(spdm_ctx);
	void *scratch_buffer = (void *)malloc(scratch_buffer_size);

	LOG_INF("SPDM scratch_buffer size=%d ptr=%p", scratch_buffer_size, scratch_buffer);
	assert(scratch_buffer != NULL);

	libspdm_set_scratch_buffer(spdm_ctx, scratch_buffer, scratch_buffer_size);
	libspdm_data_parameter_t parameter;
	spdm_version_number_t spdm_version[3];
	uint64_t data64;
	uint32_t data32;
	uint16_t data16;
	uint8_t data8;

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	spdm_version[0] = SPDM_MESSAGE_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
	spdm_version[1] = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
	spdm_version[2] = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_SPDM_VERSION, &parameter, &spdm_version, sizeof(spdm_version));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data8 = 0;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter, &data8, sizeof(data8));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data32 = 0 |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP |
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP |
		0;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &data32, sizeof(data32));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data64 = 0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_CAPABILITY_RTT_US, &parameter, &data64, sizeof(data64));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data8 = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter, &data8, sizeof(data8));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data32 = 0 |
		SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256 |
		SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &data32, sizeof(data32));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data32 = 0 | \
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &data32, sizeof(data32));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data32 = 0 | \
		SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
		SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &data32, sizeof(data32));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 |
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
		0;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
		  &data16, sizeof(data16));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 |
		SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
		SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter, &data16, sizeof(data16));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 | \
		SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter, &data16, sizeof(data16));

	/*
	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 | \
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &data16, sizeof(data16));
	*/
	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data16 = 0 | \
		SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH |
		0;
	libspdm_set_data (spdm_ctx, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16, sizeof(data16));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
		  &data8, sizeof(data8));

	libspdm_zero_mem(&parameter, sizeof(parameter));
	parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
	data8 = 0xF0;
	libspdm_set_data(spdm_ctx, LIBSPDM_DATA_HEARTBEAT_PERIOD, &parameter,
		  &data8, sizeof(data8));

	/* certificate */
	void *data = NULL;
	size_t data_size = 0;
	libspdm_read_responder_public_certificate_chain(
			SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
			SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
			&data, &data_size,
			NULL, NULL);
	parameter.additional_data[0] = 0;
	libspdm_set_data(spdm_ctx,
			LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
			&parameter, data, data_size);

	#if 0
	libspdm_register_get_response_func(
		spdm_ctx, spdm_get_response_vendor_defined_request);
	#endif

	libspdm_register_session_state_callback_func(
		spdm_ctx, spdm_server_session_state_callback);
	libspdm_register_connection_state_callback_func(
		spdm_ctx, spdm_server_connection_state_callback);

#if LIBSPDM_CHECK_SPDM_CONTEXT
	ret = libspdm_check_context(spdm_ctx);
	if (!ret) {
		LOG_ERR("SPDM Context check invalid");
		goto cleanup;
	}
#endif

	return spdm_ctx;
cleanup:
	libspdm_deinit_context(spdm_ctx);
	free(spdm_ctx);
	return NULL;
}

uint8_t mctp_spdm_cmd_handler(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_params ext_params)
{
	static void *spdm_context = NULL, *app_context = NULL;
	if (spdm_context == NULL) {
		spdm_context = spdm_server_init(mctp_p);
		if (spdm_context == NULL) {
			LOG_ERR("SPDM context init failed");
			return MCTP_ERROR;
		}
		app_context = malloc(sizeof(struct app_context_t));
		libspdm_data_parameter_t parameter;
		libspdm_zero_mem(&parameter, sizeof(parameter));
		parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
		libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter, &app_context, sizeof(&app_context));
	}

	if (app_context == NULL) {
		LOG_ERR("App context init failed");
		return MCTP_ERROR;
	}

	((struct app_context_t *)app_context)->mctp_p = mctp_p;
	((struct app_context_t *)app_context)->ext_params = ext_params;
	((struct app_context_t *)app_context)->recv_buffer = malloc(len);
	((struct app_context_t *)app_context)->recv_buffer_size = len;
	memcpy(((struct app_context_t *)app_context)->recv_buffer, buf, len);

	libspdm_return_t ret = libspdm_responder_dispatch_message(spdm_context);
	if (LIBSPDM_STATUS_IS_ERROR(ret)) {
		LOG_ERR("libspdm_responder_dispatch_message ret=%08x", ret);
		return MCTP_ERROR;
	}

	return MCTP_SUCCESS;
}

