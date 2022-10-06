/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMResponder.h"
#include "SPDM/ResponseCmd/SPDMResponseCmd.h"

LOG_MODULE_REGISTER(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

/*
 * SPDM Messaging Protocol Flow:
 *
 *             ┌───────────┐                 ┌───────────┐
 *             │ Requester │                 │ Responder │
 *             └─────┬─────┘                 └──────┬────┘
 *                  ┌┴┐                             │
 *                  └┬┴────────GET_VERSION────────►┌┴┐
 *                  ┌┴┐◄─────────VERSION───────────┴┬┘
 *                  └┬┴─────GET_CAPABILITIES──────►┌┴┐
 *                  ┌┴┐◄───────CAPABILITEIES───────┴┬┘
 *                  └┬┴───NEGOTIATE_ALGORITHMS────►┌┴┐
 *                  ┌┴┐◄────────ALGORITHMS─────────┴┬┘
 * ┌────────────┐---│ │-----------------------------│---+
 * │If supported│   └┬┴──────────GET_DIGESTS──────►┌┴┐  |
 * └────────────/   ┌┴┐◄─────────DIGESTS───────────┴┬┘  |
 * |┌────────────┐--│ │-----------------------------│-+ |
 * |│If necessary│  │ │                             │ | |
 * |└────────────/  └┬┴──────GET_CERTIFICATES─────►┌┴┐| |
 * ||               ┌┴┐◄────────CERTIFICATES───────┴┬┘| |
 * |+---------------│ │-----------------------------│-+ |
 * |                └┬┴─────────CHALLENGE─────────►┌┴┐  |
 * |                ┌┴┐◄──────CHALLENGE_AUTH───────┴┬┘  |
 * +----------------│ │-----------------------------│---+
 * ┌────────────┐---│ │-----------------------------│---+
 * │If supported│   │ │                             │   |
 * └────────────/   └┬┴───────GET_MEASUREMENTS─────┬┴┐  |
 * |                 │◄─────────MEASUREMENTS───────┴┬┘  |
 * +-----------------│------------------------------│---+
 *                   │                              │
 *
 */

static void handler(void *ctx, void *req, void *rsp);

static struct spdm_context *find_spdm_context(uint8_t bus, uint8_t src_eid)
{
	extern struct spdm_context *context_rsp_oo;
	return context_rsp_oo;
}

int handle_spdm_mctp_message(uint8_t bus, uint8_t src_eid, void *buffer, size_t *length)
{
	struct spdm_context *context = NULL;
	struct spdm_message req_msg;
	struct spdm_message rsp_msg;

	/* Lookup Context by bus/src_eid */
	context = find_spdm_context(bus, src_eid);

	k_msleep(10);
	if (context) {
		/* Execute the message */
		memcpy(&req_msg.header, (uint8_t *)buffer+1, sizeof(req_msg.header));
		spdm_buffer_init(&req_msg.buffer, *length - 1 - 4);
		spdm_buffer_init(&rsp_msg.buffer, 0);

		memcpy(&rsp_msg.header, (uint8_t *)buffer + 1, sizeof(req_msg.header));
		spdm_buffer_append_array(&req_msg.buffer,
				(uint8_t *)buffer+1+sizeof(req_msg.header),
				*length-1-sizeof(req_msg.header));
		handler(context, &req_msg, &rsp_msg);

		/* Fill-in the response */
		*(uint8_t *)buffer = 0x05;
		memcpy((uint8_t *)buffer + 1, &rsp_msg.header, sizeof(rsp_msg.header));
		memcpy((uint8_t *)buffer + 1 + sizeof(rsp_msg.header), rsp_msg.buffer.data, rsp_msg.buffer.write_ptr);
		*length = 1 + sizeof(rsp_msg.header) + rsp_msg.buffer.write_ptr;

		spdm_buffer_release(&rsp_msg.buffer);
		spdm_buffer_release(&req_msg.buffer);

		return 0;
	}

	return -1;
}

static void handler(void *ctx, void *req, void *rsp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;

	if (req_msg->header.spdm_version != SPDM_VERSION) {
		return;
	}

	rsp_msg->header.spdm_version = SPDM_VERSION;
	rsp_msg->header.request_response_code = SPDM_RSP_ERROR;
	rsp_msg->header.param1 = SPDM_ERROR_CODE_UNSUPPORTED_REQUEST;
	rsp_msg->header.param2 = 0;

	switch (context->connection_state) {
	case SPDM_STATE_NOT_READY:
		/* Only accept GET_VERSION command*/
		if (req_msg->header.request_response_code == SPDM_REQ_GET_VERSION) {
			spdm_handle_get_version(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_GOT_VERSION;
		}
		break;
	case SPDM_STATE_GOT_VERSION:
		if (req_msg->header.request_response_code == SPDM_REQ_GET_CAPABILITIES) {
			spdm_handle_get_capabilities(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_GOT_CAPABILITIES;
		} else if (req_msg->header.request_response_code == SPDM_REQ_GET_VERSION) {
			// Reset the protocol
			spdm_handle_get_version(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_GOT_VERSION;
		}
		break;
	case SPDM_STATE_GOT_CAPABILITIES:
		if (req_msg->header.request_response_code == SPDM_REQ_NEGOTIATE_ALGORITHMS) {
			spdm_handle_negotiate_algorithms(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_NEGOTIATED_ALGORITHMS;
		} else if (req_msg->header.request_response_code == SPDM_REQ_GET_VERSION) {
			// Reset the protocol
			spdm_handle_get_version(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_GOT_VERSION;
		}
		break;
	case SPDM_STATE_NEGOTIATED_ALGORITHMS:
		/* Expecting GET_DIGEST (if supported) or GET_MEASUREMENT message */
		if (req_msg->header.request_response_code == SPDM_REQ_GET_DIGESTS) {
			spdm_handle_get_digests(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_GOT_DIGESTS;
		} else if (req_msg->header.request_response_code == SPDM_REQ_GET_MEASUREMENTS) {
			spdm_handle_get_measurements(context, req_msg, rsp_msg);
			// context->connection_state = SPDM_STATE_SESSION_ESTABLISHED;
		} else if (req_msg->header.request_response_code == SPDM_REQ_GET_VERSION) {
			// Reset the protocol
			spdm_handle_get_version(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_GOT_VERSION;
		}
		break;
	case SPDM_STATE_GOT_DIGESTS:
		if (req_msg->header.request_response_code == SPDM_REQ_GET_CERTIFICATE) {
			spdm_handle_get_certificate(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_GOT_CERTIFICATE;
		} else if (req_msg->header.request_response_code == SPDM_REQ_CHALLENGE) {
			spdm_handle_challenge(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_CHANLLENGED;
		} else if (req_msg->header.request_response_code == SPDM_REQ_GET_VERSION) {
			// Reset the protocol
			spdm_handle_get_version(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_GOT_VERSION;
		}
		break;
	case SPDM_STATE_GOT_CERTIFICATE:
		if (req_msg->header.request_response_code == SPDM_REQ_GET_CERTIFICATE) {
			spdm_handle_get_certificate(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_GOT_CERTIFICATE;
		} else if (req_msg->header.request_response_code == SPDM_REQ_CHALLENGE) {
			spdm_handle_challenge(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_CHANLLENGED;
		} else if (req_msg->header.request_response_code == SPDM_REQ_GET_VERSION) {
			// Reset the protocol
			spdm_handle_get_version(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_GOT_VERSION;
		}
		break;
	case SPDM_STATE_CHANLLENGED:
		if (req_msg->header.request_response_code == SPDM_REQ_GET_MEASUREMENTS) {
			spdm_handle_get_measurements(context, req_msg, rsp_msg);
			// context->connection_state = SPDM_STATE_SESSION_ESTABLISHED;
		} else if (req_msg->header.request_response_code == SPDM_REQ_GET_VERSION) {
			// Reset the protocol
			spdm_handle_get_version(context, req_msg, rsp_msg);
			context->connection_state = SPDM_STATE_GOT_VERSION;
		} else if (req_msg->header.request_response_code == SPDM_REQ_GET_DIGESTS) {
			spdm_handle_get_digests(context, req_msg, rsp_msg);
		} else if (req_msg->header.request_response_code == SPDM_REQ_GET_CERTIFICATE) {
			spdm_handle_get_certificate(context, req_msg, rsp_msg);
		}
		break;
	default:
		LOG_ERR("Current State=%d doesn't accept message type 0x%x",
				context->connection_state,
				req_msg->header.request_response_code);
		break;
	}
}

