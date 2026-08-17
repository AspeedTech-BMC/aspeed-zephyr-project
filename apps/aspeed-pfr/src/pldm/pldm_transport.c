/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <string.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include "cmd_interface/device_manager.h"
#include "mctp/mctp_base_protocol.h"
#include "pldm.h"
#include "pldm_transport.h"

LOG_MODULE_REGISTER(pfr_pldm_transport, CONFIG_LOG_DEFAULT_LEVEL);

#define PFR_PLDM_MSG_TYPE 0x01
/*
 * The i3c-mctp-target chardev on the other end (caliptra-mcu-sw's
 * i3c_mctp.rs) caps a read at I3C_MCTP_TX_PACKET_LEN=68 bytes and only
 * strips our trailing PEC byte when the packet it read is STRICTLY SHORTER
 * than 68 (its rx_payload_without_pec() only handles its own 69-on-the-wire
 * -> truncated-to-68 case). A 4-byte header + 63-byte payload + our 1-byte
 * PEC is exactly 68 bytes, so that PEC byte is kept as if it were payload,
 * corrupting the reassembled message. Keep our wire packets under 68 bytes:
 * 4 + 62 + 1 = 67.
 */
#define PFR_PLDM_MCTP_PAYLOAD 62

struct pldm_transport_context {
	uint8_t message[CONFIG_PFR_PLDM_MAX_MESSAGE_SIZE];
	size_t length;
	uint8_t source_eid;
	uint8_t target_eid;
	uint8_t source_addr;
	uint8_t msg_tag;
	uint8_t tag_owner;
	uint8_t next_seq;
	bool active;
};

static bool pldm_is_i3c(const mctp *mctp_inst)
{
	return (mctp_inst->medium_type == MCTP_MEDIUM_TYPE_I3C) ||
		(mctp_inst->medium_type == MCTP_MEDIUM_TYPE_I3C_TARGET);
}

static bool pldm_is_i3c_target(const mctp *mctp_inst)
{
	return mctp_inst->medium_type == MCTP_MEDIUM_TYPE_I3C_TARGET;
}

static struct pldm_transport_context *pldm_get_context(mctp *mctp_inst)
{
	struct pldm_transport_context *ctx = mctp_inst->pldm_transport;

	if (ctx == NULL) {
		ctx = calloc(1, sizeof(*ctx));
		mctp_inst->pldm_transport = ctx;
	}

	return ctx;
}

static void pldm_reset_context(struct pldm_transport_context *ctx)
{
	ctx->length = 0;
	ctx->active = false;
}

bool pldm_transport_process_packet(mctp *mctp_inst, struct cmd_packet *packet)
{
	struct mctp_base_protocol_transport_i3c_header *header;
	struct pldm_transport_context *ctx;
	mctp_ext_params ext_params = { 0 };
	uint8_t *payload;
	size_t payload_len;

	if ((mctp_inst == NULL) || (packet == NULL) || !pldm_is_i3c(mctp_inst) ||
	    (packet->pkt_size <= sizeof(*header)))
		return false;

	header = (struct mctp_base_protocol_transport_i3c_header *)packet->data;
	payload = packet->data + sizeof(*header);
	/* The i3c-mctp chardev transport does not put a PEC on the wire; the
	 * kernel driver owns PEC generation/verification, so packet->data holds
	 * only the transport header and the raw MCTP payload.
	 */
	payload_len = packet->pkt_size - sizeof(*header);

	ctx = pldm_get_context(mctp_inst);
	if (ctx == NULL)
		return header->som && (payload[0] == PFR_PLDM_MSG_TYPE);

	/* A non-SOM packet belongs to PLDM only when it matches the active exchange. */
	if (!header->som &&
	    (!ctx->active || (header->msg_tag != ctx->msg_tag) ||
	     (header->tag_owner != ctx->tag_owner) ||
	     (header->source_eid != ctx->source_eid)))
		return false;

	if (header->som && (payload[0] != PFR_PLDM_MSG_TYPE))
		return false;

	if ((header->header_version != MCTP_BASE_PROTOCOL_SUPPORTED_HDR_VERSION) ||
	    (header->rsvd != 0)) {
		pldm_reset_context(ctx);
		return true;
	}

	if (header->som) {
		ctx->length = 0;
		ctx->source_eid = header->source_eid;
		ctx->target_eid = header->destination_eid;
		ctx->source_addr = packet->dest_addr;
		ctx->msg_tag = header->msg_tag;
		ctx->tag_owner = header->tag_owner;
		ctx->next_seq = (header->packet_seq + 1) & 0x3;
		ctx->active = true;
	} else if (header->packet_seq != ctx->next_seq) {
		LOG_WRN("PLDM packet sequence mismatch");
		pldm_reset_context(ctx);
		return true;
	} else {
		ctx->next_seq = (ctx->next_seq + 1) & 0x3;
	}

	if ((ctx->length + payload_len) > sizeof(ctx->message)) {
		LOG_ERR("PLDM message exceeds %u bytes", (unsigned int)sizeof(ctx->message));
		pldm_reset_context(ctx);
		return true;
	}

	memcpy(ctx->message + ctx->length, payload, payload_len);
	ctx->length += payload_len;

	if (!header->eom)
		return true;

	ext_params.tag_owner = header->tag_owner ? 0 : 1;
	ext_params.msg_tag = header->msg_tag;
	ext_params.ep = header->source_eid;
	ext_params.type = mctp_inst->medium_type;
	ext_params.i3c_ext_params.addr = packet->dest_addr;

	LOG_DBG("PLDM message received: eid=%02x len=%u", header->source_eid,
		(unsigned int)ctx->length);
	mctp_pldm_cmd_handler(mctp_inst, ctx->message, ctx->length, ext_params);
	pldm_reset_context(ctx);
	return true;
}

uint8_t mctp_send_msg(mctp *mctp_inst, uint8_t *buf, uint16_t len,
			      mctp_ext_params ext_params)
{
	struct mctp_interface *interface;
	struct cmd_packet packet = { 0 };
	uint8_t packet_seq = 0;
	uint8_t source_eid;
	size_t offset = 0;
	int result;

	if ((mctp_inst == NULL) || (buf == NULL) || (len == 0) ||
	    !pldm_is_i3c(mctp_inst))
		return MCTP_ERROR;

	interface = &mctp_inst->mctp_wrapper.mctp_interface;
	result = device_manager_get_device_eid(interface->device_manager,
		DEVICE_MANAGER_SELF_DEVICE_NUM);
	if (ROT_IS_ERROR(result))
		return MCTP_ERROR;
	source_eid = result;

	while (offset < len) {
		size_t payload_len = MIN((size_t)PFR_PLDM_MCTP_PAYLOAD, len - offset);
		bool som = (offset == 0);
		bool eom = ((offset + payload_len) == len);

		result = mctp_base_protocol_construct_i3c(
			buf + offset, payload_len, packet.data, sizeof(packet.data),
			mctp_inst->medium_conf.i3c_conf.addr, ext_params.ep, source_eid,
			som, eom, packet_seq, ext_params.msg_tag, ext_params.tag_owner,
			mctp_inst->medium_conf.i3c_conf.addr, pldm_is_i3c_target(mctp_inst));
		if (ROT_IS_ERROR(result))
			return MCTP_ERROR;

		packet.pkt_size = result;
		packet.dest_addr = mctp_inst->medium_conf.i3c_conf.addr;
		packet.state = CMD_VALID_PACKET;
		if (mctp_send_packet(mctp_inst, &packet) != MCTP_SUCCESS)
			return MCTP_ERROR;

		offset += payload_len;
		packet_seq = (packet_seq + 1) & 0x3;
	}

	return MCTP_SUCCESS;
}

void pldm_transport_deinit(mctp *mctp_inst)
{
	if ((mctp_inst != NULL) && (mctp_inst->pldm_transport != NULL)) {
		free(mctp_inst->pldm_transport);
		mctp_inst->pldm_transport = NULL;
	}
}

void pldm_transport_reset(mctp *mctp_inst)
{
	if ((mctp_inst != NULL) && (mctp_inst->pldm_transport != NULL))
		pldm_reset_context(mctp_inst->pldm_transport);
}
