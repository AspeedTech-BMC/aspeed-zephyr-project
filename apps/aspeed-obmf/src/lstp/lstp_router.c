/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>

#include "lstp_common.h"
#include "lstp_backend.h"
#include "lstp_channel.h"
#include "lstp_router.h"
#include "lstp_usb.h"
#include "lstp_task.h"
#include "lstp_transaction.h"

LOG_MODULE_REGISTER(lstp_router, LOG_LEVEL_ERR);

static atomic_t lstp_host_active;

/* Indexed by channel ID; slot 0 is the router's own management channel. */
static const struct lstp_channel *channels[LSTP_NUM_CHANNELS];

static const struct lstp_channel mgmt_channel = {
	.id = LSTP_MGMT_CHANNEL_ID,
	.type = LSTP_CHANNEL_TYPE_MANAGEMENT,
	.name = "Management",
};

/* The BMC cannot toggle channels; every exported channel stays enabled. */
#define LSTP_CHANNEL_ENABLED true

const struct lstp_channel *lstp_router_channel(uint8_t channel_id)
{
	return channel_id < ARRAY_SIZE(channels) ? channels[channel_id] : NULL;
}

static lstp_status_t write_channel_config_helper(uint8_t channel_id,
						 struct lstp_channel_config_blob *cfg,
						 size_t cfg_size)
{
	const struct lstp_channel *ch = lstp_router_channel(channel_id);

	if (ch == NULL) {
		return LSTP_STATUS_ERROR;
	}

	if (cfg_size < sizeof(cfg->channel_type) + sizeof(cfg->channel_enabled)) {
		return LSTP_STATUS_ERROR;
	}

	if ((lstp_channel_type_t)cfg->channel_type != ch->type ||
	    (bool)cfg->channel_enabled != LSTP_CHANNEL_ENABLED) {
		return LSTP_STATUS_NOT_SUPPORTED;
	}

	return LSTP_STATUS_SUCCESS;
}

void lstp_router_init(void)
{
	LOG_INF("Initializing OBMF Router");
	lstp_transaction_init();

	channels[LSTP_MGMT_CHANNEL_ID] = &mgmt_channel;
	STRUCT_SECTION_FOREACH(lstp_channel, ch) {
		if (ch->id == LSTP_CHANNEL_ID_NONE) {
			continue;
		}
		if (ch->id >= ARRAY_SIZE(channels) || channels[ch->id] != NULL) {
			LOG_ERR("Channel %s has a bad or duplicate ID %u", ch->name, ch->id);
			continue;
		}
		channels[ch->id] = ch;
	}

	/* Init in channel ID order so bring-up is the same on every build. */
	for (size_t i = 0; i < ARRAY_SIZE(channels); i++) {
		const struct lstp_channel *ch = channels[i];

		if (ch == NULL) {
			LOG_ERR("No channel registered for ID %zu", i);
			continue;
		}
		if (ch->init != NULL) {
			int ret = ch->init();

			if (ret != 0) {
				LOG_ERR("Failed to initialize %s channel: %d", ch->name, ret);
			}
		}
	}
}

static lstp_status_t handle_read_config(struct lstp_hdr *req_hdr, uint8_t *payload, size_t payload_len,
		uint8_t *resp_buf, size_t *resp_len)
{
	if (payload_len < sizeof(struct lstp_channel_config_read_request)) {
		return LSTP_STATUS_ERROR;
	}

	struct lstp_channel_config_read_request *req = (struct lstp_channel_config_read_request *)payload;
	const struct lstp_channel *ch = lstp_router_channel(req->channel_id);

	if (ch == NULL) {
		return LSTP_STATUS_ERROR;
	}

	LOG_DBG("Read Config Request for Channel %d", req->channel_id);

	struct lstp_channel_config_blob *resp_blob = (struct lstp_channel_config_blob *)resp_buf;
	size_t offset = sizeof(struct lstp_channel_config_blob);
	size_t type_len = 0;
	lstp_status_t status = LSTP_STATUS_SUCCESS;

	memset(resp_blob->channel_name, 0, sizeof(resp_blob->channel_name));
	resp_blob->channel_type = ch->type;
	resp_blob->channel_enabled = LSTP_CHANNEL_ENABLED;
	strncpy((char *)resp_blob->channel_name, ch->name,
		sizeof(resp_blob->channel_name) - 1U);

	if (ch == &mgmt_channel) {
		struct lstp_management_config *mgmt_cfg =
			(struct lstp_management_config *)(resp_buf + offset);
		mgmt_cfg->lstp_version = LSTP_VERSION;
		mgmt_cfg->num_channels = LSTP_NUM_CHANNELS - 1;
		type_len = sizeof(struct lstp_management_config);
	} else if (ch->read_config != NULL) {
		status = ch->read_config(req, resp_buf + offset,
					 LSTP_MAX_PAYLOAD_SIZE - offset, &type_len);
		if (status != LSTP_STATUS_SUCCESS) {
			return status;
		}
	}

	*resp_len = offset + type_len;
	return status;
}

static lstp_status_t handle_write_config(uint8_t *payload, size_t payload_len)
{
	lstp_status_t status;

	if (payload_len < sizeof(struct lstp_channel_config_write_request)) {
		return LSTP_STATUS_ERROR;
	}

	struct lstp_channel_config_write_request *req =
		(struct lstp_channel_config_write_request *)payload;
	size_t cfg_size = payload_len - sizeof(*req);

	const struct lstp_channel *ch = lstp_router_channel(req->channel_id);

	if (ch == NULL) {
		return LSTP_STATUS_ERROR;
	}

	if (req->offset != 0) {
		return LSTP_STATUS_NOT_SUPPORTED;
	}

	if (cfg_size < sizeof(struct lstp_channel_config_blob)) {
		return LSTP_STATUS_ERROR;
	}

	struct lstp_channel_config_blob *cfg =
		(struct lstp_channel_config_blob *)(payload + sizeof(*req));
	status = write_channel_config_helper(req->channel_id, cfg, cfg_size);
	if (status == LSTP_STATUS_SUCCESS && ch->config_written != NULL) {
		ch->config_written();
	}

	return status;
}

static lstp_status_t handle_channel_0(struct lstp_hdr *hdr, uint8_t *payload, size_t payload_len,
		uint8_t *resp_buf, size_t *resp_len)
{
	lstp_management_cmd_t cmd = (lstp_management_cmd_t)hdr->cmd_status_code;

	switch (cmd) {
		case LSTP_MGMT_CMD_READ_CONFIG:
			return handle_read_config(hdr, payload, payload_len, resp_buf, resp_len);
		case LSTP_MGMT_CMD_WRITE_CONFIG:
			return handle_write_config(payload, payload_len);
		case LSTP_MGMT_CMD_LOCK:
			return LSTP_STATUS_NOT_SUPPORTED;
		default:
			LOG_WRN("Unknown management command: 0x%02x", cmd);
			return LSTP_STATUS_NOT_SUPPORTED;
	}
}

/* An empty response carrying only a status, for requests that are not run. */
static void lstp_router_reply_status(uint8_t channel_id, lstp_status_t status)
{
	const struct lstp_hdr resp = {
		.channel_id = channel_id,
		.cmd_status_code = (uint8_t)status | LSTP_RESPONSE_BIT,
	};

	(void)lstp_usb_send_response((const uint8_t *)&resp, sizeof(resp), K_NO_WAIT);
}

int lstp_router_receive(uint8_t *buffer, size_t len)
{
	int ret;

	if (len < sizeof(struct lstp_hdr)) {
		LOG_WRN("Received packet too small: %zu", len);
		return -EINVAL;
	}

	if (len > LSTP_MSG_SIZE) {
		LOG_ERR("Received packet too large: %zu", len);
		return -EMSGSIZE;
	}

	struct lstp_hdr *hdr = (struct lstp_hdr *)buffer;
	size_t payload_len = hdr->len_lsb | (hdr->len_msb << BYTE1_SHIFT);

	if (len < sizeof(struct lstp_hdr) + payload_len) {
		LOG_ERR("Invalid packet length: declared %zu, received %zu",
			payload_len, len - sizeof(struct lstp_hdr));
		return -EINVAL;
	}

	if (hdr->cmd_status_code & LSTP_RESPONSE_BIT) {
		if (!lstp_transaction_handle_response(buffer, len)) {
			LOG_DBG("Unmatched response packet on channel %u", hdr->channel_id);
		}
		return 0;
	}

	if (hdr->channel_id >= LSTP_NUM_CHANNELS) {
		LOG_ERR("Invalid channel id: %u", hdr->channel_id);
		lstp_router_reply_status(hdr->channel_id, LSTP_STATUS_NOT_SUPPORTED);
		return -EINVAL;
	}

	atomic_set(&lstp_host_active, 1);

	const uint8_t req_channel_id = hdr->channel_id;

	LOG_DBG("Routing packet for channel %d", hdr->channel_id);

	/*
	 * Legacy Flashrom uses channel 0 for SPI opcodes 0x0..0x7 and matches the
	 * reply on channel 0, so only the request is rerouted.
	 */
	if (LSTP_HAS_SPI_CHANNEL && hdr->channel_id == LSTP_MGMT_CHANNEL_ID &&
	    (hdr->cmd_status_code & LSTP_SPI_CMD_CODE_MASK) <= LSTP_SPI_CMD_END) {
		hdr->channel_id = LSTP_SPI_CHANNEL_ID;
		LOG_DBG("Backward compat: routing ch0 cmd 0x%02x to SPI",
			hdr->cmd_status_code & LSTP_SPI_CMD_CODE_MASK);
	}

	if (hdr->channel_id == LSTP_MGMT_CHANNEL_ID) {
		/* Static: this runs in the USB controller ISR, one packet at a time. */
		static uint8_t resp_buf[LSTP_MSG_SIZE];
		struct lstp_hdr *resp_hdr = (struct lstp_hdr *)resp_buf;
		size_t resp_payload_len = 0;
		lstp_status_t status;

		status = handle_channel_0(hdr, buffer + sizeof(struct lstp_hdr), payload_len,
					  resp_buf + sizeof(struct lstp_hdr), &resp_payload_len);

		resp_hdr->channel_id = hdr->channel_id;
		resp_hdr->cmd_status_code = status | LSTP_RESPONSE_BIT;
		resp_hdr->len_lsb = resp_payload_len & LSB_MASK;
		resp_hdr->len_msb = (resp_payload_len >> BYTE1_SHIFT) & LSB_MASK;

		ret = lstp_usb_send_response(resp_buf,
					     sizeof(struct lstp_hdr) + resp_payload_len,
					     K_NO_WAIT);
		if (ret < 0) {
			LOG_ERR("Failed to send OBMF management response: %d", ret);
		}
		return 0;
	}

	/* Queue peripheral requests: blocking handlers cannot run in the USB ISR. */
	ret = lstp_task_submit_req(buffer, len, req_channel_id);
	if (ret < 0) {
		/*
		 * No early status reply: replies carry no tag, so one queued now
		 * would overtake earlier requests' replies on the same channel.
		 */
		LOG_ERR("Dropping channel %u req: %s", hdr->channel_id,
			ret == -ENOMSG ? "task queue full" : "invalid length");
	}
	return ret;
}

bool lstp_router_host_active(void)
{
	return atomic_get(&lstp_host_active) != 0;
}

void lstp_router_host_reset(void)
{
	atomic_clear(&lstp_host_active);
	lstp_task_drop_requests();
	/* Purging frees slots even when the task has no request left to dequeue. */
	lstp_usb_rx_resume();

	STRUCT_SECTION_FOREACH(lstp_channel, ch) {
		if (ch->id != LSTP_CHANNEL_ID_NONE && ch->host_reset != NULL) {
			ch->host_reset();
		}
	}
}

int lstp_router_send_event(uint8_t channel_id, uint8_t command, const void *data, size_t len)
{
	struct lstp_hdr hdr = {
		.channel_id = channel_id,
		.cmd_status_code = command,
		.len_lsb = len & LSB_MASK,
		.len_msb = (len >> BYTE1_SHIFT) & LSB_MASK,
	};

	if (lstp_router_channel(channel_id) == NULL) {
		return -ENOTSUP;
	}

	if (len > LSTP_MAX_PAYLOAD_SIZE) {
		return -EINVAL;
	}

	return lstp_usb_send_event_parts(&hdr, data, len);
}
