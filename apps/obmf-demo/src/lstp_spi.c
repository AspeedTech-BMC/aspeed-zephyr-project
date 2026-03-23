/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/drivers/spi.h>
#include <zephyr/drivers/spi_nor.h>
#include <string.h>

#include "lstp_common.h"
#include "lstp_spi.h"

LOG_MODULE_REGISTER(lstp_spi, LOG_LEVEL_ERR);

/* -----------------------------------------------------------------------
 * SPI device binding
 *
 * LSTP channel 1 is mapped to the SPI1 controller.
 * This implementation uses Zephyr's SPI driver API.
 *
 * The Linux LSTP SPI host uses the CS assert/deassert bits in the LSTP
 * command byte to span a single flash transaction across multiple USB
 * packets. Keep that state here and map it to Zephyr's SPI bus locking /
 * hold-on-CS support so sequences such as:
 *
 *   CS_ASSERT + zero-length read
 *   WRITE 0x9f
 *   READ 3 + CS_DEASSERT
 *
 * behave like the OpenSMA reference implementation.
 * ----------------------------------------------------------------------- */
#define LSTP_SPI_CHANNEL_START 1   /* SPI channel ID (Ch0=Mgmt, Ch1=SPI, Ch2=I2C, Ch3=GPIO) */

/* SPI devices with built-in CS control */
static const struct device *spi_cs0_dev;
static const struct device *spi_cs1_dev;

/* SPI configuration - default to 18.75MHz, matches OpenSMA SPI_FREQ_18_75MHZ */
static uint32_t spi_speed_hz = 18750000;
static bool spi_session_active;
static uint8_t spi_session_cs = LSTP_SPI_CS0;
static bool spi_session_first_byte;

static uint8_t flash_session_buf[6];
static size_t flash_session_buf_len;
#define SFDP_CACHE_SIZE 512U
#define SFDP_CACHE_CHUNK_SIZE 8U
static uint8_t sfdp_cache[SFDP_CACHE_SIZE];
static bool sfdp_cache_valid;

enum flash_session_cmd {
	FLASH_SESSION_CMD_NONE = 0,
	FLASH_SESSION_CMD_RDID,
	FLASH_SESSION_CMD_SFDP,
	FLASH_SESSION_CMD_READ_FAST,
	FLASH_SESSION_CMD_READ_FAST_4B,
};

static enum flash_session_cmd flash_session_cmd;
static off_t flash_session_offset;

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

static bool spi_cmd_has_assert(const struct lstp_hdr *hdr)
{
	return (hdr->cmd_status_code & LSTP_SPI_CS_ASSERT) != 0U;
}

static bool spi_cmd_has_deassert(const struct lstp_hdr *hdr)
{
	return (hdr->cmd_status_code & LSTP_SPI_CS_DEASSERT) != 0U;
}

static uint8_t spi_cmd_cs(const struct lstp_hdr *hdr)
{
	return hdr->cmd_status_code & LSTP_SPI_CS_MASK;
}

static uint32_t spi_read_count_from_payload(const uint8_t *payload)
{
	return payload[0]
	     | (payload[1] << BYTE1_SHIFT)
	     | (payload[2] << BYTE2_SHIFT)
	     | (payload[3] << BYTE3_SHIFT);
}

static off_t flash_sfdp_offset_from_cmd(const uint8_t *cmd)
{
	return ((off_t)cmd[1] << BYTE2_SHIFT)
	     | ((off_t)cmd[2] << BYTE1_SHIFT)
	     | (off_t)cmd[3];
}

static off_t flash_addr4_offset_from_cmd(const uint8_t *cmd)
{
	return ((off_t)cmd[1] << 24)
	     | ((off_t)cmd[2] << BYTE2_SHIFT)
	     | ((off_t)cmd[3] << BYTE1_SHIFT)
	     | (off_t)cmd[4];
}

static off_t flash_addr3_offset_from_cmd(const uint8_t *cmd)
{
	return ((off_t)cmd[1] << BYTE2_SHIFT)
	     | ((off_t)cmd[2] << BYTE1_SHIFT)
	     | (off_t)cmd[3];
}

static size_t get_expected_header_len(enum flash_session_cmd cmd)
{
	switch (cmd) {
	case FLASH_SESSION_CMD_RDID:
		return 1;
	case FLASH_SESSION_CMD_SFDP:
	case FLASH_SESSION_CMD_READ_FAST:
		return 5;
	case FLASH_SESSION_CMD_READ_FAST_4B:
		return 6;
	default:
		return 0;
	}
}

static bool spi_cmd_is_cs_only_read(const struct lstp_hdr *hdr,
				    const uint8_t *payload, size_t payload_len)
{
	lstp_spi_command_t cmd;

	if (payload_len < 4U) {
		return false;
	}

	cmd = (lstp_spi_command_t)(hdr->cmd_status_code & LSTP_SPI_CMD_CODE_MASK);
	if (cmd != LSTP_SPI_CMD_READ) {
		return false;
	}

	if (!spi_cmd_has_assert(hdr) && !spi_cmd_has_deassert(hdr)) {
		return false;
	}

	return spi_read_count_from_payload(payload) == 0U;
}

static void spi_apply_session_flags(struct spi_config *spi_cfg, const struct lstp_hdr *hdr)
{
	if (spi_session_active || spi_cmd_has_assert(hdr)) {
		spi_cfg->operation |= SPI_LOCK_ON | SPI_HOLD_ON_CS;
	}
}

static void spi_start_session(const struct lstp_hdr *hdr)
{
	spi_session_active = true;
	spi_session_cs = spi_cmd_cs(hdr);
	spi_session_first_byte = true;
	flash_session_cmd = FLASH_SESSION_CMD_NONE;
	flash_session_offset = 0;
	flash_session_buf_len = 0;
}

static void spi_end_session(const struct device *spi_dev, const struct spi_config *spi_cfg)
{
	int ret = spi_release(spi_dev, spi_cfg);

	if (ret != 0) {
		LOG_WRN("spi_release failed: %d", ret);
	}

	spi_session_active = false;
	flash_session_cmd = FLASH_SESSION_CMD_NONE;
	flash_session_offset = 0;
	flash_session_buf_len = 0;
}

static bool flash_session_ready(const struct device *spi_dev)
{
	if (!spi_dev) {
		return false;
	}

	if (!device_is_ready(spi_dev)) {
		LOG_ERR("Flash device not ready");
		return false;
	}

	return true;
}

int lstp_spi_init(void)
{
#if defined(CONFIG_FLASH_JESD216_API)
	const struct device *flash_dev;
	size_t offset = 0;
	int ret;

	init_spi_devices();
	flash_dev = spi_cs0_dev;
	if (!flash_session_ready(flash_dev)) {
		return -ENODEV;
	}

	while (offset < SFDP_CACHE_SIZE) {
		size_t chunk = MIN((size_t)SFDP_CACHE_CHUNK_SIZE, SFDP_CACHE_SIZE - offset);

		ret = flash_sfdp_read(flash_dev, (off_t)offset, &sfdp_cache[offset], chunk);
		if (ret != 0) {
			sfdp_cache_valid = false;
			LOG_ERR("SFDP cache fill failed at 0x%zx: %d", offset, ret);
			return ret;
		}

		offset += chunk;
	}

	sfdp_cache_valid = true;
	LOG_INF("SFDP cache ready: %u bytes", (unsigned int)SFDP_CACHE_SIZE);
	return 0;
#else
	sfdp_cache_valid = false;
	LOG_INF("SFDP cache disabled: CONFIG_FLASH_JESD216_API is off");
	return -ENOTSUP;
#endif
}

static bool handle_flash_cmd_write(const uint8_t *payload, size_t payload_len)
{
	if (!spi_session_active || spi_session_cs != LSTP_SPI_CS0 || payload_len == 0U) {
		return false;
	}

	bool is_first = spi_session_first_byte;
	spi_session_first_byte = false;

	if (is_first && payload_len == 1U && payload[0] == SPI_NOR_CMD_RDID) {
		flash_session_cmd = FLASH_SESSION_CMD_RDID;
		flash_session_offset = 0;
		flash_session_buf[0] = payload[0];
		flash_session_buf_len = 1U;
		LOG_DBG("Flash wrapper: latched JEDEC ID command");
		return true;
	}

	size_t expected_fast = get_expected_header_len(FLASH_SESSION_CMD_READ_FAST);
	if ((flash_session_cmd == FLASH_SESSION_CMD_READ_FAST &&
	     flash_session_buf_len < expected_fast) ||
	    (is_first && payload[0] == SPI_NOR_CMD_READ_FAST)) {
		size_t copy_len;

		if (flash_session_cmd != FLASH_SESSION_CMD_READ_FAST) {
			flash_session_cmd = FLASH_SESSION_CMD_READ_FAST;
			flash_session_offset = 0;
			flash_session_buf_len = 0;
		}

		copy_len = MIN(payload_len, expected_fast - flash_session_buf_len);
		memcpy(&flash_session_buf[flash_session_buf_len], payload, copy_len);
		flash_session_buf_len += copy_len;

		if (flash_session_buf[0] != SPI_NOR_CMD_READ_FAST) {
			flash_session_cmd = FLASH_SESSION_CMD_NONE;
			flash_session_offset = 0;
			flash_session_buf_len = 0;
			return false;
		}

		if (flash_session_buf_len < expected_fast) {
			LOG_DBG("Flash wrapper: partial READ_FAST header %u/%u bytes",
				(unsigned int)flash_session_buf_len,
				(unsigned int)expected_fast);
			return true;
		}

		flash_session_offset = flash_addr3_offset_from_cmd(flash_session_buf);
		LOG_DBG("Flash wrapper: latched READ_FAST at offset 0x%08lx",
			(unsigned long)flash_session_offset);
		return true;
	}

	size_t expected_fast4b = get_expected_header_len(FLASH_SESSION_CMD_READ_FAST_4B);
	if ((flash_session_cmd == FLASH_SESSION_CMD_READ_FAST_4B &&
	     flash_session_buf_len < expected_fast4b) ||
	    (is_first && payload[0] == SPI_NOR_CMD_READ_FAST_4B)) {
		size_t copy_len;

		if (flash_session_cmd != FLASH_SESSION_CMD_READ_FAST_4B) {
			flash_session_cmd = FLASH_SESSION_CMD_READ_FAST_4B;
			flash_session_offset = 0;
			flash_session_buf_len = 0;
		}

		copy_len = MIN(payload_len, expected_fast4b - flash_session_buf_len);
		memcpy(&flash_session_buf[flash_session_buf_len], payload, copy_len);
		flash_session_buf_len += copy_len;

		if (flash_session_buf[0] != SPI_NOR_CMD_READ_FAST_4B) {
			flash_session_cmd = FLASH_SESSION_CMD_NONE;
			flash_session_offset = 0;
			flash_session_buf_len = 0;
			return false;
		}

		if (flash_session_buf_len < expected_fast4b) {
			LOG_DBG("Flash wrapper: partial READ_FAST_4B header %u/%u bytes",
				(unsigned int)flash_session_buf_len,
				(unsigned int)expected_fast4b);
			return true;
		}

		flash_session_offset = flash_addr4_offset_from_cmd(flash_session_buf);
		LOG_DBG("Flash wrapper: latched READ_FAST_4B at offset 0x%08lx",
			(unsigned long)flash_session_offset);
		return true;
	}

	size_t expected_sfdp = get_expected_header_len(FLASH_SESSION_CMD_SFDP);
	if ((flash_session_cmd == FLASH_SESSION_CMD_SFDP && flash_session_buf_len < expected_sfdp) ||
	    (is_first && payload[0] == SPI_NOR_CMD_RDSFDP)) {
		size_t copy_len;

		if (flash_session_cmd != FLASH_SESSION_CMD_SFDP) {
			flash_session_cmd = FLASH_SESSION_CMD_SFDP;
			flash_session_offset = 0;
			flash_session_buf_len = 0;
		}

		copy_len = MIN(payload_len, expected_sfdp - flash_session_buf_len);
		memcpy(&flash_session_buf[flash_session_buf_len], payload, copy_len);
		flash_session_buf_len += copy_len;

		if (flash_session_buf[0] != SPI_NOR_CMD_RDSFDP) {
			flash_session_cmd = FLASH_SESSION_CMD_NONE;
			flash_session_offset = 0;
			flash_session_buf_len = 0;
			return false;
		}

		if (flash_session_buf_len < expected_sfdp) {
			LOG_DBG("Flash wrapper: partial SFDP header %u/%u bytes",
				(unsigned int)flash_session_buf_len,
				(unsigned int)expected_sfdp);
			return true;
		}

		flash_session_offset = flash_sfdp_offset_from_cmd(flash_session_buf);
		LOG_DBG("Flash wrapper: latched SFDP read at offset 0x%06lx",
			(unsigned long)flash_session_offset);
		return true;
	}

	if (is_first) {
		flash_session_cmd = FLASH_SESSION_CMD_NONE;
		flash_session_offset = 0;
		flash_session_buf_len = 0;
	}
	return false;
}

static int handle_flash_cmd_read(const struct device *spi_dev,
				 const struct spi_config *spi_cfg,
				 uint32_t read_count,
				 uint8_t *resp_payload, size_t *resp_payload_len)
{
	if (flash_session_cmd == FLASH_SESSION_CMD_NONE) {
		return -ENOTSUP;
	}

	if (!flash_session_ready(spi_dev)) {
		return -ENODEV;
	}

#if defined(CONFIG_FLASH_JESD216_API)
	int ret;

	if (flash_session_cmd == FLASH_SESSION_CMD_RDID) {
		uint8_t jedec_id[SPI_NOR_MAX_ID_LEN] = { 0 };

		ret = flash_read_jedec_id(spi_dev, jedec_id);
		if (ret != 0) {
			LOG_ERR("flash_read_jedec_id failed: %d", ret);
			return ret;
		}

		memset(resp_payload, 0, read_count);
		memcpy(resp_payload, jedec_id, MIN(read_count, sizeof(jedec_id)));
		*resp_payload_len = read_count;
		LOG_DBG("Flash wrapper: returned %u-byte JEDEC ID response", read_count);
		return 0;
	}

	if (flash_session_cmd == FLASH_SESSION_CMD_SFDP) {
		size_t available;
		size_t expected = get_expected_header_len(FLASH_SESSION_CMD_SFDP);

		if (flash_session_buf_len < expected) {
			LOG_WRN("Flash wrapper: SFDP read before full header (%u/%u bytes)",
				(unsigned int)flash_session_buf_len,
				(unsigned int)expected);
			return -EINVAL;
		}

		if (!sfdp_cache_valid) {
			LOG_ERR("Flash wrapper: SFDP cache is not available");
			return -ENODEV;
		}

		if ((size_t)flash_session_offset >= SFDP_CACHE_SIZE) {
			LOG_ERR("Flash wrapper: SFDP offset 0x%06lx outside cache",
				(unsigned long)flash_session_offset);
			return -EINVAL;
		}

		available = SFDP_CACHE_SIZE - (size_t)flash_session_offset;
		memset(resp_payload, 0, read_count);
		memcpy(resp_payload, &sfdp_cache[flash_session_offset], MIN((size_t)read_count, available));
		*resp_payload_len = read_count;
		LOG_DBG("Flash wrapper: returned %u-byte SFDP response from cache offset 0x%06lx",
			read_count, (unsigned long)flash_session_offset);
		return 0;
	}

	if (flash_session_cmd == FLASH_SESSION_CMD_READ_FAST_4B) {
		size_t expected = get_expected_header_len(FLASH_SESSION_CMD_READ_FAST_4B);
		if (flash_session_buf_len < expected) {
			LOG_WRN("Flash wrapper: READ_FAST_4B before full header (%u/%u bytes)",
				(unsigned int)flash_session_buf_len,
				(unsigned int)expected);
			return -EINVAL;
		}

		ret = flash_read(spi_dev, flash_session_offset, resp_payload, read_count);
		if (ret != 0) {
			LOG_ERR("flash_read failed at 0x%08lx: %d",
				(unsigned long)flash_session_offset, ret);
			return ret;
		}

		*resp_payload_len = read_count;
		LOG_DBG("Flash wrapper: returned %u-byte READ_FAST_4B response from 0x%08lx",
			read_count, (unsigned long)flash_session_offset);
		return 0;
	}

	if (flash_session_cmd == FLASH_SESSION_CMD_READ_FAST) {
		size_t expected = get_expected_header_len(FLASH_SESSION_CMD_READ_FAST);
		if (flash_session_buf_len < expected) {
			LOG_WRN("Flash wrapper: READ_FAST before full header (%u/%u bytes)",
				(unsigned int)flash_session_buf_len,
				(unsigned int)expected);
			return -EINVAL;
		}

		ret = flash_read(spi_dev, flash_session_offset, resp_payload, read_count);
		if (ret != 0) {
			LOG_ERR("flash_read failed at 0x%08lx: %d",
				(unsigned long)flash_session_offset, ret);
			return ret;
		}

		*resp_payload_len = read_count;
		LOG_DBG("Flash wrapper: returned %u-byte READ_FAST response from 0x%08lx",
			read_count, (unsigned long)flash_session_offset);
		return 0;
	}

	return -ENOTSUP;
#else
	ARG_UNUSED(read_count);
	ARG_UNUSED(resp_payload);
	ARG_UNUSED(resp_payload_len);
	LOG_ERR("CONFIG_FLASH_JESD216_API is disabled");
	return -ENOTSUP;
#endif
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
				uint8_t *resp_payload, size_t *resp_payload_len,
				bool *send_response)
{
	*resp_payload_len = 0;
	*send_response = true;

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

	if (spi_session_active && spi_session_cs != spi_cmd_cs(hdr)) {
		LOG_WRN("SPI CS changed mid-session: old=0x%02x new=0x%02x",
			spi_session_cs, spi_cmd_cs(hdr));
		spi_session_active = false;
	}

	spi_apply_session_flags(&spi_cfg, hdr);

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
		if (spi_cmd_has_assert(hdr)) {
			spi_start_session(hdr);
		}

		if (payload_len == 0U) {
			ret = 0;
			resp_payload[0] = 0;
			*resp_payload_len = 1;
			break;
		}

		if (handle_flash_cmd_write(payload, payload_len)) {
			ret = 0;
			resp_payload[0] = 0;
			*resp_payload_len = 1;
			LOG_DBG("SPI Write: handled by flash wrapper");
			break;
		}

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

		if (spi_cmd_has_assert(hdr)) {
			spi_start_session(hdr);
		}

		uint32_t read_count = spi_read_count_from_payload(payload);

		/* Clamp to max payload size (OpenSMA would send multiple packets) */
		if (read_count > LSTP_MAX_PAYLOAD_SIZE) {
			read_count = LSTP_MAX_PAYLOAD_SIZE;
		}

		if (read_count == 0U) {
			ret = 0;
			*send_response = !spi_cmd_is_cs_only_read(hdr, payload, payload_len);
			LOG_DBG("SPI Read: zero-length %s", *send_response ? "with response" : "CS-only");
			break;
		}

		ret = handle_flash_cmd_read(spi_dev, &spi_cfg, read_count,
					    resp_payload, resp_payload_len);
		if (ret == 0) {
			break;
		}
		if (ret != -ENOTSUP) {
			break;
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
		if (spi_cmd_has_assert(hdr)) {
			spi_start_session(hdr);
		}

		if (payload_len == 0U) {
			ret = 0;
			*resp_payload_len = 0;
			break;
		}

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
		if (spi_cmd_has_assert(hdr)) {
			spi_start_session(hdr);
		}

		if (payload_len == 0U) {
			ret = 0;
			*resp_payload_len = 0;
			break;
		}

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

	if (spi_session_active && spi_cmd_has_deassert(hdr) && (ret == 0)) {
		spi_end_session(spi_dev, &spi_cfg);
	}

	return zephyr_ret_to_lstp(ret);
}
