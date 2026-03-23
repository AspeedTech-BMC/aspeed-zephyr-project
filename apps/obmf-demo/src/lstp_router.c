/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/printk.h>
#include <string.h>

#include "lstp_common.h"
#include "lstp_router.h"
#include "lstp_usb.h"
#include "lstp_task.h"

LOG_MODULE_REGISTER(lstp_router, LOG_LEVEL_ERR);

struct lstp_channel_state {
	bool enabled;
};

static struct lstp_channel_state channels[LSTP_MAX_CHANNELS];

static bool channel_id_supported(uint8_t channel_id)
{
	return channel_id < LSTP_NUM_CHANNELS;
}

static void fill_gpio_config(uint16_t gpio_index, struct lstp_gpio_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	snprintk((char *)cfg->gpio_name, sizeof(cfg->gpio_name), "GPIO%u", gpio_index);
	cfg->direction = LSTP_GPIO_DIRECTION_OUTPUT;
	cfg->default_output = LSTP_GPIO_STATE_LOW;
	cfg->output_drive_config = LSTP_GPIO_OUTPUT_DRIVE_PUSH_PULL;
	cfg->output_persist_state = 0;
	cfg->bias_pull_config = LSTP_GPIO_BIAS_NO_PULL;
}

static lstp_status_t read_gpio_config_helper(uint16_t req_offset, uint16_t req_length,
					     uint8_t *resp_buf, size_t *resp_len)
{
	uint16_t start_pin = 0;
	uint16_t n_pins = 0;
	size_t offset = 0;

	if (req_offset == 0) {
		struct lstp_gpio_channel_config *gpio_cfg =
			(struct lstp_gpio_channel_config *)(resp_buf + offset);
		gpio_cfg->channel_num_gpio = LSTP_GPIO_NUM;
		offset += sizeof(*gpio_cfg);

		if (req_length == 0) {
			n_pins = MIN(LSTP_GPIO_NUM, LSTP_MAX_GPIOS_PER_PACKET);
		} else {
			if (req_length < sizeof(struct lstp_gpio_channel_config)) {
				return LSTP_STATUS_ERROR;
			}
			if ((req_length - sizeof(struct lstp_gpio_channel_config))
			    % sizeof(struct lstp_gpio_config) != 0) {
				return LSTP_STATUS_ERROR;
			}

			n_pins = (req_length - sizeof(struct lstp_gpio_channel_config))
				 / sizeof(struct lstp_gpio_config);
		}
	} else {
		if (req_offset < sizeof(struct lstp_gpio_channel_config)) {
			return LSTP_STATUS_ERROR;
		}
		if ((req_offset - sizeof(struct lstp_gpio_channel_config))
		    % sizeof(struct lstp_gpio_config) != 0) {
			return LSTP_STATUS_ERROR;
		}
		if (req_length % sizeof(struct lstp_gpio_config) != 0) {
			return LSTP_STATUS_ERROR;
		}

		start_pin = (req_offset - sizeof(struct lstp_gpio_channel_config))
			    / sizeof(struct lstp_gpio_config);
		n_pins = req_length / sizeof(struct lstp_gpio_config);
	}

	if (start_pin >= LSTP_GPIO_NUM) {
		return LSTP_STATUS_ERROR;
	}

	if ((size_t)n_pins > LSTP_MAX_GPIOS_PER_PACKET) {
		return LSTP_STATUS_ERROR;
	}

	if ((size_t)start_pin + (size_t)n_pins > LSTP_GPIO_NUM) {
		n_pins = LSTP_GPIO_NUM - start_pin;
	}

	for (uint16_t i = 0; i < n_pins; i++) {
		if (offset + sizeof(struct lstp_gpio_config) > LSTP_MAX_PAYLOAD_SIZE) {
			return LSTP_STATUS_ERROR;
		}

		struct lstp_gpio_config *cfg =
			(struct lstp_gpio_config *)(resp_buf + offset);
		fill_gpio_config(start_pin + i, cfg);
		offset += sizeof(*cfg);
	}

	*resp_len = offset;
	return LSTP_STATUS_SUCCESS;
}

static lstp_status_t write_channel_config_helper(uint8_t channel_id,
						 struct lstp_channel_config_blob *cfg,
						 size_t cfg_size)
{
	size_t cfg_offset = 0;

	if (!channel_id_supported(channel_id)) {
		return LSTP_STATUS_ERROR;
	}

	if (cfg_size < sizeof(cfg->channel_type) + sizeof(cfg->channel_enabled)) {
		return LSTP_STATUS_ERROR;
	}

	cfg_offset += sizeof(cfg->channel_type);
	cfg_offset += sizeof(cfg->channel_enabled);

	switch ((lstp_channel_type_t)cfg->channel_type) {
	case LSTP_CHANNEL_TYPE_MANAGEMENT:
	case LSTP_CHANNEL_TYPE_SPI:
	case LSTP_CHANNEL_TYPE_GPIO:
	case LSTP_CHANNEL_TYPE_I2C:
		if ((bool)cfg->channel_enabled != channels[channel_id].enabled) {
			return LSTP_STATUS_NOT_SUPPORTED;
		}
		break;
	default:
		return LSTP_STATUS_NOT_SUPPORTED;
	}

	ARG_UNUSED(cfg_offset);
	return LSTP_STATUS_SUCCESS;
}

void lstp_router_init(void)
{
	LOG_INF("Initializing LSTP Router");
	for (int i = 0; i < LSTP_NUM_CHANNELS; i++) {
		channels[i].enabled = true; // By default all supported channels enabled
	}
}

static lstp_status_t handle_read_config(struct lstp_hdr *req_hdr, uint8_t *payload, size_t payload_len,
		uint8_t *resp_buf, size_t *resp_len)
{
	if (payload_len < sizeof(struct lstp_channel_config_read_request)) {
		return LSTP_STATUS_ERROR;
	}

	struct lstp_channel_config_read_request *req = (struct lstp_channel_config_read_request *)payload;
	if (!channel_id_supported(req->channel_id)) {
		return LSTP_STATUS_ERROR;
	}

	LOG_DBG("Read Config Request for Channel %d", req->channel_id);

	struct lstp_channel_config_blob *resp_blob = (struct lstp_channel_config_blob *)resp_buf;
	size_t offset = sizeof(struct lstp_channel_config_blob);

	memset(resp_blob->channel_name, 0, sizeof(resp_blob->channel_name));

	/* Populate response based on channel ID */
	switch (req->channel_id) {
		case 0: /* Management Channel */
		{
			resp_blob->channel_type = LSTP_CHANNEL_TYPE_MANAGEMENT;
			resp_blob->channel_enabled = channels[0].enabled;
			strncpy((char *)resp_blob->channel_name, "Management", sizeof(resp_blob->channel_name));

			struct lstp_management_config *mgmt_cfg =
				(struct lstp_management_config *)(resp_buf + offset);
			mgmt_cfg->lstp_version = LSTP_VERSION;
			mgmt_cfg->num_channels = LSTP_NUM_CHANNELS - 1;
			offset += sizeof(struct lstp_management_config);
			break;
		}

		case 1: /* SPI Channel — SPI1 */
		{
			resp_blob->channel_type = LSTP_CHANNEL_TYPE_SPI;
			resp_blob->channel_enabled = channels[1].enabled;
			strncpy((char *)resp_blob->channel_name, "SPI1", sizeof(resp_blob->channel_name));

			/*
			 * Temporary kernel workaround: the current host-side SPI
			 * discovery path expects only the base channel blob here and
			 * mis-parses the OpenSMA SPI tail {channel_num_cs, freq_hz}.
			 * Keep the SPI read-config response at 18 bytes until the
			 * kernel-side parser is fixed.
			 *
			 * Original OpenSMA-aligned implementation:
			 * if (offset + sizeof(struct lstp_spi_channel_config)
			 *     > LSTP_MAX_PAYLOAD_SIZE) {
			 *         return LSTP_STATUS_ERROR;
			 * }
			 * struct lstp_spi_channel_config *spi_cfg =
			 *         (struct lstp_spi_channel_config *)(resp_buf + offset);
			 * spi_cfg->channel_num_cs = 2;
			 * spi_cfg->freq_hz = 18750000U;
			 * offset += sizeof(struct lstp_spi_channel_config);
			 */
			break;
		}

		case 2: /* I2C Channel — i2c6 */
			resp_blob->channel_type = LSTP_CHANNEL_TYPE_I2C;
			resp_blob->channel_enabled = channels[2].enabled;
			strncpy((char *)resp_blob->channel_name, "I2C6", sizeof(resp_blob->channel_name));

			if (offset + sizeof(struct lstp_i2c_channel_config) <= LSTP_MAX_PAYLOAD_SIZE) {
				struct lstp_i2c_channel_config *i2c_cfg =
					(struct lstp_i2c_channel_config *)(resp_buf + offset);
				i2c_cfg->speed = LSTP_I2C_SPEED_FAST; /* 400 kHz default */
				offset += sizeof(struct lstp_i2c_channel_config);
			}
			break;

		case 3: /* GPIO Channel */
			resp_blob->channel_type = LSTP_CHANNEL_TYPE_GPIO;
			resp_blob->channel_enabled = channels[3].enabled;
			strncpy((char *)resp_blob->channel_name, "GPIO", sizeof(resp_blob->channel_name));
			{
				size_t gpio_resp_len = 0;
				lstp_status_t gpio_status =
					read_gpio_config_helper(req->offset, req->length,
								resp_buf + offset,
								&gpio_resp_len);
				if (gpio_status != LSTP_STATUS_SUCCESS) {
					return gpio_status;
				}
				*resp_len = offset + gpio_resp_len;
				return LSTP_STATUS_SUCCESS;
			}

		default:
			LOG_WRN("Unsupported channel configuration read: %d", req->channel_id);
			return LSTP_STATUS_NOT_SUPPORTED;
	}

	*resp_len = offset;
	return LSTP_STATUS_SUCCESS;
}

static lstp_status_t handle_write_config(uint8_t *payload, size_t payload_len)
{
	if (payload_len < sizeof(struct lstp_channel_config_write_request)) {
		return LSTP_STATUS_ERROR;
	}

	struct lstp_channel_config_write_request *req =
		(struct lstp_channel_config_write_request *)payload;
	size_t cfg_size = payload_len - sizeof(*req);

	if (!channel_id_supported(req->channel_id)) {
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
	return write_channel_config_helper(req->channel_id, cfg, cfg_size);
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

void lstp_router_receive(uint8_t *buffer, size_t len)
{
	if (len < sizeof(struct lstp_hdr)) {
		LOG_WRN("Received packet too small: %zu", len);
		return;
	}

	struct lstp_hdr *hdr = (struct lstp_hdr *)buffer;

	/* Ignore responses */
	if (hdr->cmd_status_code & LSTP_RESPONSE_BIT) {
		LOG_DBG("Ignoring response packet");
		return;
	}

	size_t payload_len = hdr->len_lsb | (hdr->len_msb << BYTE1_SHIFT);
	if (len < sizeof(struct lstp_hdr) + payload_len) {
		LOG_ERR("Invalid packet length: declared %zu, received %zu", payload_len, len - sizeof(struct lstp_hdr));
		return;
	}

	if (hdr->channel_id >= LSTP_NUM_CHANNELS) {
		LOG_ERR("Invalid channel id: %u", hdr->channel_id);
		return;
	}

	uint8_t *payload = buffer + sizeof(struct lstp_hdr);

	/* Allocate response buffer */
	uint8_t resp_buf[LSTP_MSG_SIZE];
	struct lstp_hdr *resp_hdr = (struct lstp_hdr *)resp_buf;
	uint8_t *resp_payload = resp_buf + sizeof(struct lstp_hdr);
	size_t resp_payload_len = 0;

	lstp_status_t status = LSTP_STATUS_NOT_SUPPORTED;

	LOG_DBG("Routing packet for channel %d", hdr->channel_id);

	/*
	 * Backward compatibility: Flashrom (NV_SMA_SPI) may use channel ID = 0
	 * in the request packet. For backward compatibility, treat channel 0
	 * commands 0x0..0x7 as SPI commands.
	 * Matches OpenSMA lstp_router.cpp receive_helper logic.
	 */
	uint8_t effective_channel_id = hdr->channel_id;
	if (hdr->channel_id == 0) {
		uint8_t cmd_code = hdr->cmd_status_code & LSTP_SPI_CMD_CODE_MASK;
		if (cmd_code <= LSTP_SPI_CMD_END) {
			effective_channel_id = 1;
			hdr->channel_id = 1;
			LOG_DBG("Backward compat: routing ch0 cmd 0x%02x to SPI", cmd_code);
		}
	}

	switch (effective_channel_id) {
		case 0: /* Management Channel */
			status = handle_channel_0(hdr, payload, payload_len, resp_payload, &resp_payload_len);

			/* Format and send Mgmt response synchronously */
			resp_hdr->channel_id = hdr->channel_id;
			resp_hdr->cmd_status_code = status | LSTP_RESPONSE_BIT;
			resp_hdr->len_lsb = resp_payload_len & LSB_MASK;
			resp_hdr->len_msb = (resp_payload_len >> BYTE1_SHIFT) & LSB_MASK;

			int ret = lstp_usb_send(resp_buf, sizeof(struct lstp_hdr) + resp_payload_len);
			if (ret < 0) {
				LOG_ERR("Failed to send LSTP Mgmt response: %d", ret);
			}
			break;

		case 1: /* SPI Channel (SPI1) — route to background task (thread context) */
			/*
			 * SPI transfers are blocking calls and cannot run in USB
			 * endpoint ISR context. Submit to the task queue.
			 */
			if (lstp_task_submit_req(buffer, len) < 0) {
				LOG_ERR("Task queue full, dropping SPI req");
			}
			break;

		case 2: /* I2C Channel (i2c6) — route to background task (thread context) */
			/*
			 * I2C transfers are blocking calls (i2c_write_read etc.) and
			 * cannot run in USB endpoint ISR context. Submit to the task
			 * queue, same as GPIO.
			 */
			if (lstp_task_submit_req(buffer, len) < 0) {
				LOG_ERR("Task queue full, dropping I2C req");
			}
			break;

		case 3: /* GPIO Hardware Channel */
			/* Submit the entire packet buffer to the background task queue */
			if (lstp_task_submit_req(buffer, len) < 0) {
				LOG_ERR("Task queue full, dropping GPIO req");
			}
			/* Do NOT send a synchronous response here, lstp_task handles it */
			break;

		default:
			LOG_WRN("Routing for channel %d not implemented", hdr->channel_id);
			break;
	}
}
