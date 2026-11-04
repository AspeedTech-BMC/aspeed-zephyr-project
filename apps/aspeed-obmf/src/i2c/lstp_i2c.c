/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/dt-bindings/i2c/i2c.h>
#include <string.h>

#include "lstp/lstp_common.h"
#include "lstp/lstp_backend.h"
#include "lstp/lstp_channel.h"
#include "lstp/lstp_usb.h"

LOG_MODULE_REGISTER(lstp_i2c, LOG_LEVEL_ERR);

#define LSTP_I2C_NUM_CHANNELS  1   /* Number of I2C channels exposed */
#define LSTP_I2C_SMBUS_BLOCK_MAX 32U /* SMBus block-read data limit */
#define LSTP_I2C_HELD_MAX 4U

/* Advertise the bus speed the devicetree configures. */
#define LSTP_I2C_BUS_HZ DT_PROP_OR(LSTP_I2C_NODE, clock_frequency, I2C_BITRATE_FAST)
#define LSTP_I2C_SPEED                                           \
	((LSTP_I2C_BUS_HZ >= I2C_BITRATE_HIGH)      ? LSTP_I2C_SPEED_HIGH      : \
	 (LSTP_I2C_BUS_HZ >= I2C_BITRATE_FAST_PLUS) ? LSTP_I2C_SPEED_FAST_PLUS : \
	 (LSTP_I2C_BUS_HZ >= I2C_BITRATE_FAST)      ? LSTP_I2C_SPEED_FAST      : \
						      LSTP_I2C_SPEED_STANDARD)

static const struct device *lstp_i2c_devs[LSTP_I2C_NUM_CHANNELS] = {
	DEVICE_DT_GET(LSTP_I2C_NODE),
};

/*
 * The Aspeed controller always ends the last message of a transfer with STOP,
 * so a NOSTOP write cannot be put on the bus by itself. It is held instead and
 * goes out with subsequent writes and a final request to the same target.
 * Keep message boundaries so each held write gets its own address phase.
 */
static struct {
	uint8_t count;
	uint32_t session; /* USB session of the host that sent the write */
	uint8_t addr;
	size_t len;
	size_t lengths[LSTP_I2C_HELD_MAX];
	uint8_t data[LSTP_MAX_PAYLOAD_SIZE];
} i2c_held;

static int i2c_transfer_held(const struct device *dev, const struct i2c_msg *final,
			   uint8_t num_final)
{
	struct i2c_msg msgs[LSTP_I2C_HELD_MAX + 2U];
	uint8_t count = i2c_held.count;
	size_t offset = 0;

	for (uint8_t i = 0; i < count; i++) {
		msgs[i].buf = i2c_held.data + offset;
		msgs[i].len = i2c_held.lengths[i];
		msgs[i].flags = I2C_MSG_WRITE | (i ? I2C_MSG_RESTART : 0);
		offset += i2c_held.lengths[i];
	}
	for (uint8_t i = 0; i < num_final; i++) {
		msgs[count] = final[i];
		msgs[count++].flags |= I2C_MSG_RESTART;
	}
	msgs[count - 1U].flags |= I2C_MSG_STOP;
	i2c_held.count = 0;
	i2c_held.len = 0;

	return i2c_transfer(dev, msgs, count, i2c_held.addr);
}

/* Flush failures belong to the same host transfer as the next request. */
static atomic_t i2c_held_write_errors;

static int i2c_flush_held(const struct device *dev)
{
	if (!i2c_held.count) {
		return 0;
	}

	int ret = i2c_transfer_held(dev, NULL, 0);

	if (ret != 0) {
		atomic_inc(&i2c_held_write_errors);
		LOG_ERR("Held NOSTOP write to 0x%02x failed: %d", i2c_held.addr, ret);
	}
	return ret;
}

static int i2c_transfer_final_msgs(const struct device *dev, uint8_t addr,
				   struct i2c_msg *msgs, uint8_t num_msgs)
{
	if (i2c_held.count && i2c_held.addr == addr) {
		return i2c_transfer_held(dev, msgs, num_msgs);
	}

	int ret = i2c_flush_held(dev);

	if (ret != 0) {
		return ret;
	}
	return i2c_transfer(dev, msgs, num_msgs, addr);
}

static int i2c_transfer_final(const struct device *dev, uint8_t addr,
			      uint8_t *buf, size_t len, uint8_t flags)
{
	struct i2c_msg msg = {
		.buf   = buf,
		.len   = len,
		.flags = flags | I2C_MSG_STOP,
	};

	return i2c_transfer_final_msgs(dev, addr, &msg, 1);
}

static const struct device *get_i2c_dev(uint8_t channel_id)
{
	int idx = (int)channel_id - LSTP_I2C_CHANNEL_ID;

	if (idx < 0 || idx >= LSTP_I2C_NUM_CHANNELS) {
		return NULL;
	}
	return lstp_i2c_devs[idx];
}

static lstp_status_t zephyr_ret_to_lstp(int ret)
{
	if (ret == 0) {
		return LSTP_STATUS_SUCCESS;
	}
	if (ret == -ETIMEDOUT) {
		return LSTP_STATUS_TIMEOUT;
	}
	if (ret == -EBUSY) {
		return LSTP_STATUS_BUSY;
	}
	if (ret == -ENXIO) {
		/* The Aspeed driver reports an address/data NAK as -ENXIO. */
		return LSTP_STATUS_NAK;
	}
#if !defined(CONFIG_SOC_AST2700_SSP) && !defined(CONFIG_SOC_AST2700_A1_SSP) && \
	!defined(CONFIG_SOC_AST2705_SSP) && !defined(CONFIG_SOC_AST1040_CM4) && \
	!defined(CONFIG_SOC_AST1080_CM4)
	/* Match the driver's AST2600 path; AST2700 uses -EAGAIN for ABNORMAL. */
	if (ret == -EAGAIN) {
		return LSTP_STATUS_ARB_LOST;
	}
#endif
	return LSTP_STATUS_ERROR;
}

static lstp_status_t lstp_i2c_receive_request(uint8_t channel_id,
				      struct lstp_hdr *hdr,
				      uint8_t *payload, size_t payload_len,
				      uint8_t *resp_payload, size_t *resp_payload_len,
				      bool *send_response)
{
	ARG_UNUSED(send_response);

	*resp_payload_len = 0;

	const struct device *dev = get_i2c_dev(channel_id);

	if (!dev || !device_is_ready(dev)) {
		LOG_ERR("I2C dev for channel %d not ready", channel_id);
		return LSTP_STATUS_ERROR;
	}

	if (payload_len > LSTP_MAX_PAYLOAD_SIZE) {
		return LSTP_STATUS_ERROR;
	}

	lstp_i2c_command_t cmd =
		(lstp_i2c_command_t)(hdr->cmd_status_code & LSTP_I2C_CMD_MASK);

	bool no_stop = (hdr->cmd_status_code & LSTP_I2C_NOSTOP_FLAG) != 0;

	int ret = 0;

	/* Every transfer request starts with the target address; 7-bit only. */
	if (cmd != LSTP_I2C_CMD_BUS_RECOVERY && payload_len >= 1U && payload[0] > 0x7FU) {
		LOG_WRN("I2C address 0x%02x is not 7-bit", payload[0]);
		return LSTP_STATUS_ERROR;
	}

	/* A write held for a host that has since reset never reaches the bus. */
	if (i2c_held.count && i2c_held.session != lstp_usb_session()) {
		i2c_held.count = 0;
		i2c_held.len = 0;
	}

	switch (cmd) {

	case LSTP_I2C_CMD_BUS_RECOVERY:
		return LSTP_STATUS_NOT_SUPPORTED;

	case LSTP_I2C_CMD_READ: {
		if (payload_len < sizeof(struct lstp_i2c_read_request)) {
			return LSTP_STATUS_ERROR;
		}

		const struct lstp_i2c_read_request *req =
			(const struct lstp_i2c_read_request *)payload;
		uint16_t read_len = req->read_len;

		if (read_len > LSTP_MAX_PAYLOAD_SIZE) {
			return LSTP_STATUS_TOO_LARGE;
		}

		ret = i2c_transfer_final(dev, req->address, resp_payload, read_len,
					 I2C_MSG_READ);

		if (ret == 0) {
			*resp_payload_len = read_len;
		}

		LOG_DBG("I2C Read addr=0x%02x len=%u ret=%d", req->address, read_len, ret);
		return zephyr_ret_to_lstp(ret);
	}

	case LSTP_I2C_CMD_WRITE: {
		if (payload_len < sizeof(struct lstp_i2c_write_request)) {
			return LSTP_STATUS_ERROR;
		}

		const struct lstp_i2c_write_request *req =
			(const struct lstp_i2c_write_request *)payload;
		uint8_t *write_data = payload + sizeof(struct lstp_i2c_write_request);
		size_t   write_len  = payload_len - sizeof(struct lstp_i2c_write_request);

		/*
		 * A zero-length write is an SMBus quick write: address phase only,
		 * so probing never puts a data byte into the target.
		 */
		if (no_stop) {
			if (i2c_held.count && i2c_held.addr != req->address) {
				ret = i2c_flush_held(dev);
				if (ret != 0) {
					return zephyr_ret_to_lstp(ret);
				}
			}
			if (i2c_held.count == LSTP_I2C_HELD_MAX ||
			    write_len > LSTP_MAX_PAYLOAD_SIZE - i2c_held.len) {
				/* Splitting would insert a STOP into the host transfer. */
				i2c_held.count = 0;
				i2c_held.len = 0;
				return LSTP_STATUS_TOO_LARGE;
			}
			i2c_held.session = lstp_usb_session();
			i2c_held.addr = req->address;
			i2c_held.lengths[i2c_held.count++] = write_len;
			memcpy(i2c_held.data + i2c_held.len, write_data, write_len);
			i2c_held.len += write_len;
			LOG_DBG("I2C Write addr=0x%02x len=%zu held (NOSTOP)",
				req->address, write_len);
			return LSTP_STATUS_SUCCESS;
		}

		ret = i2c_transfer_final(dev, req->address, write_data, write_len,
					 I2C_MSG_WRITE);

		LOG_DBG("I2C Write addr=0x%02x len=%zu ret=%d",
			req->address, write_len, ret);
		return zephyr_ret_to_lstp(ret);
	}

	case LSTP_I2C_CMD_READ_RECV_LEN: {
		if (payload_len < sizeof(struct lstp_i2c_read_recv_len_request)) {
			return LSTP_STATUS_ERROR;
		}

		const struct lstp_i2c_read_recv_len_request *req =
			(const struct lstp_i2c_read_recv_len_request *)payload;

		/*
		 * KNOWN LIMITATION: one transaction sized for the count byte plus
		 * the SMBus block maximum; only the 1 + count bytes the target
		 * announced go back. Unlike Linux I2C_M_RECV_LEN the read does not
		 * stop at count: Zephyr has no receive-length read and the Aspeed
		 * driver always ends the last message with STOP, so the target is
		 * clocked for all 33 bytes (side effects on FIFO/mailbox targets,
		 * a trailing PEC is lost). Needs driver support to fix.
		 * A count of 0 or above the SMBus limit is a protocol error, as in Linux.
		 */
		BUILD_ASSERT(1U + LSTP_I2C_SMBUS_BLOCK_MAX <= LSTP_MAX_PAYLOAD_SIZE);
		ret = i2c_transfer_final(dev, req->address, resp_payload,
					 1U + LSTP_I2C_SMBUS_BLOCK_MAX, I2C_MSG_READ);
		/* SMBus block counts are 1..32. */
		if (ret == 0 && (resp_payload[0] == 0U ||
				 resp_payload[0] > LSTP_I2C_SMBUS_BLOCK_MAX)) {
			ret = -EPROTO;
		}
		if (ret == 0) {
			*resp_payload_len = 1U + (size_t)resp_payload[0];
		}

		LOG_DBG("I2C ReadRecvLen addr=0x%02x ret=%d", req->address, ret);
		return zephyr_ret_to_lstp(ret);
	}

	case LSTP_I2C_CMD_WRITE_READ: {
		if (payload_len < sizeof(struct lstp_i2c_write_read_request)) {
			return LSTP_STATUS_ERROR;
		}

		const struct lstp_i2c_write_read_request *req =
			(const struct lstp_i2c_write_read_request *)payload;
		uint8_t *write_data = payload + sizeof(struct lstp_i2c_write_read_request);
		size_t   write_len  =
			payload_len - sizeof(struct lstp_i2c_write_read_request);
		uint16_t read_len   = req->read_len;

		if (read_len > LSTP_MAX_PAYLOAD_SIZE) {
			return LSTP_STATUS_TOO_LARGE;
		}

		struct i2c_msg msgs[2] = {
			{
				.buf = write_data,
				.len = write_len,
				.flags = I2C_MSG_WRITE,
			},
			{
				.buf = resp_payload,
				.len = read_len,
				.flags = I2C_MSG_READ | I2C_MSG_RESTART | I2C_MSG_STOP,
			},
		};

		ret = i2c_transfer_final_msgs(dev, req->address, msgs, ARRAY_SIZE(msgs));
		if (ret == 0) {
			*resp_payload_len = read_len;
		}

		LOG_DBG("I2C WriteRead addr=0x%02x wlen=%zu rlen=%u ret=%d",
			req->address, write_len, read_len, ret);
		return zephyr_ret_to_lstp(ret);
	}

	default:
		return LSTP_STATUS_NOT_SUPPORTED;
	}
}

static lstp_status_t lstp_i2c_receive(uint8_t channel_id,
				      struct lstp_hdr *hdr,
				      uint8_t *payload, size_t payload_len,
				      uint8_t *resp_payload, size_t *resp_payload_len,
				      bool *send_response)
{
	lstp_status_t status = lstp_i2c_receive_request(channel_id, hdr, payload, payload_len,
						     resp_payload, resp_payload_len, send_response);

	/* A rejected request must not leave writes for a later request. */
	if (status != LSTP_STATUS_SUCCESS) {
		i2c_held.count = 0;
		i2c_held.len = 0;
	}
	return status;
}

static lstp_status_t lstp_i2c_read_config(const struct lstp_channel_config_read_request *req,
					  uint8_t *buf, size_t cap, size_t *len)
{
	struct lstp_i2c_channel_config *i2c_cfg = (struct lstp_i2c_channel_config *)buf;

	ARG_UNUSED(req);

	*len = 0;
	if (sizeof(*i2c_cfg) <= cap) {
		i2c_cfg->speed = LSTP_I2C_SPEED;
		*len = sizeof(*i2c_cfg);
	}
	return LSTP_STATUS_SUCCESS;
}

LSTP_CHANNEL_DEFINE(lstp_i2c_channel,
	.id = LSTP_I2C_CHANNEL_ID,
	.type = LSTP_CHANNEL_TYPE_I2C,
	.name = LSTP_I2C_CHANNEL_NAME,
	.read_config = lstp_i2c_read_config,
	.receive = lstp_i2c_receive,
);
