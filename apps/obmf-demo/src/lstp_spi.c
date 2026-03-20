/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/spi.h>
#include <string.h>

#include "lstp_common.h"
#include "lstp_spi.h"

LOG_MODULE_REGISTER(lstp_spi, LOG_LEVEL_DBG);

/* -----------------------------------------------------------------------
 * SPI device binding
 *
 * LSTP channel 1 is mapped to the SPI1 controller.
 * This implementation uses Zephyr's SPI driver API.
 *
 * CS control is handled by the SPI controller via spi1@0 and spi1@1 devices.
 * ----------------------------------------------------------------------- */
#define LSTP_SPI_CHANNEL_START 1   /* SPI channel ID (Ch0=Mgmt, Ch1=SPI, Ch2=I2C, Ch3=GPIO) */

/* SPI devices with built-in CS control */
static const struct device *spi_cs0_dev;
static const struct device *spi_cs1_dev;

/* SPI configuration - default to 18.75MHz, matches OpenSMA SPI_FREQ_18_75MHZ */
static uint32_t spi_speed_hz = 18750000;

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

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

static void init_spi_devices(void)
{
	if (!spi_cs0_dev) {
		spi_cs0_dev = device_get_binding("spi1@0");
		if (!spi_cs0_dev) {
			LOG_ERR("Failed to get spi1@0 device");
		}
	}

	if (!spi_cs1_dev) {
		spi_cs1_dev = device_get_binding("spi1@1");
		if (!spi_cs1_dev) {
			LOG_ERR("Failed to get spi1@1 device");
		}
	}
}

static const struct device *get_spi_device(uint8_t cs_bits)
{
	uint8_t cs_sel = cs_bits & LSTP_SPI_CS_MASK;

	init_spi_devices();

	switch (cs_sel) {
	case LSTP_SPI_CS0:
		return spi_cs0_dev;
	case LSTP_SPI_CS1:
		return spi_cs1_dev;
	default:
		LOG_WRN("Unsupported CS select: 0x%02x", cs_sel);
		return NULL;
	}
}

/* -----------------------------------------------------------------------
 * lstp_spi_receive
 *
 * Implements OpenSMA's LstpRouter::receive_spi → Flashrom::handle_tx.
 *
 * Command byte layout (from OpenSMA flashrom.h):
 *   Bits [7:6] = CS select (LSTP_SPI_CS_MASK)
 *   Bit  [5]   = CS deassert flag (LSTP_SPI_CS_DEASSERT)
 *   Bit  [4]   = CS assert flag (LSTP_SPI_CS_ASSERT)
 *   Bits [3:0] = Command code (LSTP_SPI_CMD_CODE_MASK)
 *
 * CS is handled automatically by the SPI controller.
 * ----------------------------------------------------------------------- */
lstp_status_t lstp_spi_receive(uint8_t channel_id,
				struct lstp_hdr *hdr,
				uint8_t *payload, size_t payload_len,
				uint8_t *resp_payload, size_t *resp_payload_len)
{
	*resp_payload_len = 0;

	/* Get the appropriate SPI device based on CS selection */
	const struct device *spi_dev = get_spi_device(hdr->cmd_status_code);
	if (!spi_dev || !device_is_ready(spi_dev)) {
		LOG_ERR("SPI device not ready");
		return LSTP_STATUS_ERROR;
	}

	if (payload_len > LSTP_MAX_PAYLOAD_SIZE) {
		return LSTP_STATUS_ERROR;
	}

	lstp_spi_command_t cmd =
		(lstp_spi_command_t)(hdr->cmd_status_code & LSTP_SPI_CMD_CODE_MASK);

	int ret = 0;

	/* Configure SPI transfer - CS is handled by controller */
	struct spi_config spi_cfg = {
		.frequency = spi_speed_hz,
		.operation = SPI_OP_MODE_MASTER | SPI_WORD_SET(8) | SPI_TRANSFER_MSB,
		.slave = 0,
		.cs = NULL,
	};

	switch (cmd) {

	/* ------------------------------------------------------------------
	 * Config: Return current SPI speed and additional config data
	 * Request:  empty
	 * Response: [speed_hz : uint32_t] (4 bytes) + 8 bytes additional data (12 bytes total)
	 * Matches OpenSMA Flashrom::handle_tx SPI_CMD_CONFIG.
	 *
	 * NOTE: The additional 8 bytes are zero-padded to work around a kernel
	 * driver bug that expects 12 bytes total instead of just the 4-byte
	 * frequency value.
	 * ------------------------------------------------------------------ */
	case LSTP_SPI_CMD_CONFIG: {
		if (LSTP_MAX_PAYLOAD_SIZE >= 12) {
			/* Bytes 0-3: SPI frequency (little-endian) */
			resp_payload[0] = (uint8_t)(spi_speed_hz & 0xFF);
			resp_payload[1] = (uint8_t)((spi_speed_hz >> BYTE1_SHIFT) & 0xFF);
			resp_payload[2] = (uint8_t)((spi_speed_hz >> BYTE2_SHIFT) & 0xFF);
			resp_payload[3] = (uint8_t)((spi_speed_hz >> BYTE3_SHIFT) & 0xFF);
			/* Bytes 4-11: Additional padding (8 bytes) - workaround for driver bug */
			resp_payload[4] = 0x00;
			resp_payload[5] = 0x00;
			resp_payload[6] = 0x00;
			resp_payload[7] = 0x00;
			resp_payload[8] = 0x00;
			resp_payload[9] = 0x00;
			resp_payload[10] = 0x00;
			resp_payload[11] = 0x00;
			*resp_payload_len = 12;
		}
		LOG_DBG("SPI Config: speed=%u Hz", spi_speed_hz);
		return LSTP_STATUS_SUCCESS;
	}

	/* ------------------------------------------------------------------
	 * Write: Send N bytes from payload
	 * Request:  [N bytes of write data]
	 * Response: [0x00] (1 byte status)
	 * Matches OpenSMA Flashrom::handle_tx SPI_CMD_WRITE.
	 * ------------------------------------------------------------------ */
	case LSTP_SPI_CMD_WRITE: {
		const struct spi_buf tx_buf = {
			.buf = payload,
			.len = payload_len,
		};
		const struct spi_buf_set tx_set = {
			.buffers = &tx_buf,
			.count = 1,
		};

		ret = spi_write(spi_dev, &spi_cfg, &tx_set);
		if (ret == 0) {
			/* Send success response: [0x00] */
			resp_payload[0] = 0;
			*resp_payload_len = 1;
		}

		LOG_DBG("SPI Write: len=%zu ret=%d", payload_len, ret);
		break;
	}

	/* ------------------------------------------------------------------
	 * Read: Read N bytes into response buffer
	 * Request:  [read_count : uint32_t] (4 bytes, little-endian)
	 * Response: [read_count bytes] (may span multiple packets in OpenSMA)
	 *
	 * OpenSMA reads in chunks of SPI_MAX_DATA_LEN (508 bytes), sending
	 * multiple responses for large reads. This simplified implementation
	 * reads up to LSTP_MAX_PAYLOAD_SIZE in a single packet.
	 * Matches OpenSMA Flashrom::handle_tx SPI_CMD_READ.
	 * ------------------------------------------------------------------ */
	case LSTP_SPI_CMD_READ: {
		if (payload_len < 4) {
			return LSTP_STATUS_ERROR;
		}

		uint32_t read_count = payload[0]
				    | (payload[1] << BYTE1_SHIFT)
				    | (payload[2] << BYTE2_SHIFT)
				    | (payload[3] << BYTE3_SHIFT);

		/* Clamp to max payload size (OpenSMA would send multiple packets) */
		if (read_count > LSTP_MAX_PAYLOAD_SIZE) {
			read_count = LSTP_MAX_PAYLOAD_SIZE;
		}

		const struct spi_buf rx_buf = {
			.buf = resp_payload,
			.len = read_count,
		};
		const struct spi_buf_set rx_set = {
			.buffers = &rx_buf,
			.count = 1,
		};

		ret = spi_read(spi_dev, &spi_cfg, &rx_set);
		if (ret == 0) {
			*resp_payload_len = read_count;
		}

		LOG_DBG("SPI Read: count=%u ret=%d", read_count, ret);
		break;
	}

	/* ------------------------------------------------------------------
	 * WriteRead: Send M bytes and receive M bytes back
	 * Request:  [M bytes of write data]
	 * Response: [M bytes of read data]
	 * Matches OpenSMA Flashrom::handle_tx SPI_CMD_WRITE_READ.
	 * ------------------------------------------------------------------ */
	case LSTP_SPI_CMD_WRITE_READ: {
		const struct spi_buf tx_buf = {
			.buf = payload,
			.len = payload_len,
		};
		const struct spi_buf_set tx_set = {
			.buffers = &tx_buf,
			.count = 1,
		};

		const struct spi_buf rx_buf = {
			.buf = resp_payload,
			.len = payload_len,
		};
		const struct spi_buf_set rx_set = {
			.buffers = &rx_buf,
			.count = 1,
		};

		ret = spi_transceive(spi_dev, &spi_cfg, &tx_set, &rx_set);
		if (ret == 0) {
			*resp_payload_len = payload_len;
		}

		LOG_DBG("SPI WriteRead: len=%zu ret=%d", payload_len, ret);
		break;
	}

	/* ------------------------------------------------------------------
	 * PostedWrite: Send N bytes, no response expected
	 * Request:  [N bytes of write data]
	 * Response: none (fire-and-forget)
	 * Matches OpenSMA Flashrom::handle_tx SPI_CMD_POSTED_WRITE.
	 * ------------------------------------------------------------------ */
	case LSTP_SPI_CMD_POSTED_WRITE: {
		const struct spi_buf tx_buf = {
			.buf = payload,
			.len = payload_len,
		};
		const struct spi_buf_set tx_set = {
			.buffers = &tx_buf,
			.count = 1,
		};

		ret = spi_write(spi_dev, &spi_cfg, &tx_set);
		/* No response for posted write */
		*resp_payload_len = 0;

		LOG_DBG("SPI PostedWrite: len=%zu ret=%d", payload_len, ret);
		break;
	}

	default:
		LOG_ERR("Unknown SPI command: 0x%02x", cmd);
		return LSTP_STATUS_NOT_SUPPORTED;
	}

	return zephyr_ret_to_lstp(ret);
}
