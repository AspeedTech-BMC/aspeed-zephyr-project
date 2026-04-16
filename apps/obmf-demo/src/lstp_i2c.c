/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/i2c.h>
#include <string.h>

#include "lstp_common.h"
#include "lstp_i2c.h"

LOG_MODULE_REGISTER(lstp_i2c, LOG_LEVEL_ERR);

/* -----------------------------------------------------------------------
 * I2C channel → Zephyr device binding table
 *
 * LSTP channel 2 is the first (and only) I2C channel, mapped to i2c0.
 * This is the Zephyr equivalent of OpenSMA's compile-time GpioSetup table.
 *
 * To add more buses, extend this array and add cases in handle_read_config.
 * ----------------------------------------------------------------------- */
#define LSTP_I2C_CHANNEL_START 2   /* First LSTP channel ID used for I2C */
#define LSTP_I2C_NUM_CHANNELS  1   /* Number of I2C channels exposed */

static const struct device *lstp_i2c_devs[LSTP_I2C_NUM_CHANNELS] = {
	DEVICE_DT_GET(DT_NODELABEL(i2c6)),  /* LSTP channel 2 → i2c6 */
};

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static const struct device *get_i2c_dev(uint8_t channel_id)
{
	int idx = (int)channel_id - LSTP_I2C_CHANNEL_START;

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
	return LSTP_STATUS_ERROR;
}

/* -----------------------------------------------------------------------
 * lstp_i2c_receive
 *
 * Implements OpenSMA's LstpRouter::receive_i2c synchronously.
 *
 * Request header layout (from OpenSMA lstp_common.h):
 *   cmd_status_code bits:
 *     [7]   = request/response bit (already stripped by caller)
 *     [6]   = NoStop flag (I2C_MSG_RESTART instead of I2C_MSG_STOP)
 *     [5:0] = command (LSTP_I2C_CMD_MASK = 0xBF strips bits 7 and 6)
 *
 * Note: read_len in OpenSMA is bounded to LstpMaxPayloadSize. We enforce
 * the same limit (LSTP_MAX_PAYLOAD_SIZE).
 * ----------------------------------------------------------------------- */
lstp_status_t lstp_i2c_receive(uint8_t channel_id,
				struct lstp_hdr *hdr,
				uint8_t *payload, size_t payload_len,
				uint8_t *resp_payload, size_t *resp_payload_len)
{
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

	/* Bit 6: NoStop — use I2C repeated-start (no STOP between write and read) */
	bool no_stop = (hdr->cmd_status_code & LSTP_I2C_NOSTOP_FLAG) != 0;

	int ret = 0;

	switch (cmd) {

	/* ------------------------------------------------------------------
	 * BusRecovery — not supported (matches OpenSMA)
	 * ------------------------------------------------------------------ */
	case LSTP_I2C_CMD_BUS_RECOVERY:
		return LSTP_STATUS_NOT_SUPPORTED;

	/* ------------------------------------------------------------------
	 * Read: {address, read_len} → [read_len bytes]
	 * QuickRead (read_len == 0): address probe with zero-length read.
	 * Matches OpenSMA receive_i2c LstpI2cCommand::Read.
	 * ------------------------------------------------------------------ */
	case LSTP_I2C_CMD_READ: {
		if (payload_len < sizeof(struct lstp_i2c_read_request)) {
			return LSTP_STATUS_ERROR;
		}

		const struct lstp_i2c_read_request *req =
			(const struct lstp_i2c_read_request *)payload;
		uint16_t read_len = req->read_len;

		if (read_len > LSTP_MAX_PAYLOAD_SIZE) {
			return LSTP_STATUS_ERROR;
		}

		if (read_len == 0) {
			/* QuickRead: address probe, zero-length, just send STOP */
			struct i2c_msg msg = {
				.buf   = resp_payload,
				.len   = 0,
				.flags = I2C_MSG_READ | I2C_MSG_STOP,
			};
			ret = i2c_transfer(dev, &msg, 1, req->address);
		} else {
			ret = i2c_read(dev, resp_payload, read_len, req->address);
		}

		if (ret == 0) {
			*resp_payload_len = read_len;
		}

		LOG_DBG("I2C Read addr=0x%02x len=%u ret=%d", req->address, read_len, ret);
		return zephyr_ret_to_lstp(ret);
	}

	/* ------------------------------------------------------------------
	 * Write: {address} + N bytes → empty response
	 * QuickWrite (N == 0): address probe with zero-length write.
	 * Matches OpenSMA receive_i2c LstpI2cCommand::Write.
	 * ------------------------------------------------------------------ */
	case LSTP_I2C_CMD_WRITE: {
		if (payload_len < sizeof(struct lstp_i2c_write_request)) {
			return LSTP_STATUS_ERROR;
		}

		const struct lstp_i2c_write_request *req =
			(const struct lstp_i2c_write_request *)payload;
		uint8_t *write_data = payload + sizeof(struct lstp_i2c_write_request);
		size_t   write_len  = payload_len - sizeof(struct lstp_i2c_write_request);

		if (write_len == 0) {
			/*
			 * QuickWrite: the host is probing device presence.
			 *
			 * Use i2c_write_read (write reg 0, read 1 byte) — this is
			 * exactly what the Zephyr I2C shell `read_byte` does.  A bare
			 * i2c_read or zero-length write both fail on devices that
			 * require a register address write phase before responding.
			 */
			uint8_t reg = 0;
			uint8_t dummy;
			ret = i2c_write_read(dev, req->address, &reg, 1, &dummy, 1);
			LOG_DBG("QuickWrite probe (write_read reg0) addr=0x%02x ret=%d",
				req->address, ret);
		} else if (no_stop) {
			/*
			 * NoStop (repeated-start): send write without STOP.
			 * Matches OpenSMA's I2cFlags::NoStop.
			 */
			struct i2c_msg msg = {
				.buf   = write_data,
				.len   = write_len,
				.flags = I2C_MSG_WRITE,
			};
			ret = i2c_transfer(dev, &msg, 1, req->address);
		} else {
			ret = i2c_write(dev, write_data, write_len, req->address);
		}

		LOG_DBG("I2C Write addr=0x%02x len=%zu ret=%d",
			req->address, write_len, ret);
		return zephyr_ret_to_lstp(ret);
	}

	/* ------------------------------------------------------------------
	 * ReadRecvLen: {address} → SMBus block read.
	 * First received byte is the count, followed by that many bytes.
	 * Matches OpenSMA receive_i2c LstpI2cCommand::ReadRecvLen.
	 * ------------------------------------------------------------------ */
	case LSTP_I2C_CMD_READ_RECV_LEN: {
		if (payload_len < sizeof(struct lstp_i2c_read_recv_len_request)) {
			return LSTP_STATUS_ERROR;
		}

		const struct lstp_i2c_read_recv_len_request *req =
			(const struct lstp_i2c_read_recv_len_request *)payload;

		/*
		 * Read the full max payload into the response buffer.
		 * The first byte returned is the byte count (SMBus convention).
		 * OpenSMA reads (UsbLstpMsgSize - sizeof(LstpHdr)) bytes.
		 */
		uint16_t read_len = (uint16_t)LSTP_MAX_PAYLOAD_SIZE;

		ret = i2c_read(dev, resp_payload, read_len, req->address);
		if (ret == 0) {
			/* Clamp actual response to count byte + data */
			uint8_t count = resp_payload[0];
			*resp_payload_len = 1U + (size_t)count;
			if (*resp_payload_len > LSTP_MAX_PAYLOAD_SIZE) {
				*resp_payload_len = LSTP_MAX_PAYLOAD_SIZE;
			}
		}

		LOG_DBG("I2C ReadRecvLen addr=0x%02x ret=%d", req->address, ret);
		return zephyr_ret_to_lstp(ret);
	}

	/* ------------------------------------------------------------------
	 * WriteRead: {address, read_len} + M bytes → [read_len bytes]
	 * Matches OpenSMA receive_i2c LstpI2cCommand::WriteRead.
	 * ------------------------------------------------------------------ */
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
			return LSTP_STATUS_ERROR;
		}

		ret = i2c_write_read(dev, req->address,
				     write_data, write_len,
				     resp_payload, read_len);
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
