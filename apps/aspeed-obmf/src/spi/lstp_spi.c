/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

/*
 * LSTP SPI channel, read-only. The BMC drives it as a raw SPI master, but
 * nothing is clocked out on the bus here: the opcode it sends between CS
 * assert and deassert is looked up in flash_ops[] and served through the
 * Zephyr flash API (JEDEC ID, SFDP, data reads). Any other opcode, and every
 * full-duplex transfer, is answered with LSTP_STATUS_NOT_SUPPORTED.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/drivers/spi_nor.h>
#include <zephyr/sys/byteorder.h>
#include <string.h>

#include "lstp/lstp_common.h"
#include "lstp/lstp_backend.h"
#include "lstp/lstp_channel.h"

LOG_MODULE_REGISTER(lstp_spi, LOG_LEVEL_ERR);

#define LSTP_SPI_DEVICE(node_id, prop, idx) \
	DEVICE_DT_GET(DT_PHANDLE_BY_IDX(node_id, prop, idx)),

static const struct device *const spi_devices[] = {
	DT_FOREACH_PROP_ELEM(LSTP_BACKEND_NODE, spi_devices, LSTP_SPI_DEVICE)
};

#define LSTP_SPI_FLASH_NODE DT_PHANDLE_BY_IDX(LSTP_BACKEND_NODE, spi_devices, 0)

/* Advertised to the host: the DT upper bound; the driver may run the bus slower. */
static const uint32_t spi_speed_hz =
	COND_CODE_1(LSTP_HAS_SPI_CHANNEL,
		    (DT_PROP_OR(LSTP_SPI_FLASH_NODE, spi_max_frequency, 18750000)),
		    (18750000));

enum flash_op_kind {
	FLASH_OP_RDID,
	FLASH_OP_SFDP,
	FLASH_OP_READ,
};

/* hdr_len counts the opcode, address and dummy bytes before the data. */
struct flash_op {
	uint8_t opcode;
	uint8_t kind;
	uint8_t hdr_len;
	uint8_t addr_len;
};

static const struct flash_op flash_ops[] = {
	{ SPI_NOR_CMD_RDID,         FLASH_OP_RDID, 1, 0 },
	{ SPI_NOR_CMD_RDSFDP,       FLASH_OP_SFDP, 5, 3 },
	{ SPI_NOR_CMD_READ,         FLASH_OP_READ, 4, 3 },
	{ SPI_NOR_CMD_READ_4B,      FLASH_OP_READ, 5, 4 },
	{ SPI_NOR_CMD_READ_FAST,    FLASH_OP_READ, 5, 3 },
	{ SPI_NOR_CMD_READ_FAST_4B, FLASH_OP_READ, 6, 4 },
};

#define FLASH_OP_MAX_HDR_LEN 6U

/* One CS-assert..deassert transaction; the header may span several packets. */
static bool spi_session_active;
static const struct flash_op *flash_session_op;
static uint8_t flash_session_hdr[FLASH_OP_MAX_HDR_LEN];
static size_t flash_session_hdr_len;
static uint32_t flash_session_offset;
static uint32_t flash_size; /* 0 until lstp_spi_init() reads the page layout */

#define SFDP_CACHE_SIZE 512U
#define SFDP_CACHE_CHUNK_SIZE 8U
static uint8_t sfdp_cache[SFDP_CACHE_SIZE];
static bool sfdp_cache_valid;

static lstp_status_t zephyr_ret_to_lstp(int ret)
{
	if (ret == 0) {
		return LSTP_STATUS_SUCCESS;
	}
	if (ret == -ENOTSUP) {
		return LSTP_STATUS_NOT_SUPPORTED;
	}
	if (ret == -ETIMEDOUT) {
		return LSTP_STATUS_TIMEOUT;
	}
	if (ret == -EBUSY) {
		return LSTP_STATUS_BUSY;
	}
	return LSTP_STATUS_ERROR;
}

/* The channel exports a single device on CS0 (see lstp_backend.h). */
static const struct device *get_spi_device(uint8_t cs_bits)
{
	uint8_t cs_sel = cs_bits & LSTP_SPI_CS_MASK;

	if (cs_sel != LSTP_SPI_CS0) {
		LOG_WRN("Unsupported CS select: 0x%02x", cs_sel);
		return NULL;
	}

	return spi_devices[0];
}

static bool spi_cmd_has_assert(const struct lstp_hdr *hdr)
{
	return (hdr->cmd_status_code & LSTP_SPI_CS_ASSERT) != 0U;
}

static bool spi_cmd_has_deassert(const struct lstp_hdr *hdr)
{
	return (hdr->cmd_status_code & LSTP_SPI_CS_DEASSERT) != 0U;
}

static uint32_t spi_read_count_from_payload(const uint8_t *payload)
{
	return (uint32_t)payload[0]
	     | ((uint32_t)payload[1] << BYTE1_SHIFT)
	     | ((uint32_t)payload[2] << BYTE2_SHIFT)
	     | ((uint32_t)payload[3] << BYTE3_SHIFT);
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

static const struct flash_op *flash_op_find(uint8_t opcode)
{
	for (size_t i = 0; i < ARRAY_SIZE(flash_ops); i++) {
		if (flash_ops[i].opcode == opcode) {
			return &flash_ops[i];
		}
	}
	return NULL;
}

/* Drop everything latched for the current transaction. */
static void spi_end_session(void)
{
	spi_session_active = false;
	flash_session_op = NULL;
	flash_session_hdr_len = 0;
	flash_session_offset = 0;
}

static void spi_start_session(void)
{
	spi_end_session();
	spi_session_active = true;
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

static int lstp_spi_init(void)
{
	const struct device *flash_dev;
	size_t offset = 0;
	int ret;

	flash_dev = spi_devices[0];
	if (!flash_session_ready(flash_dev)) {
		return -ENODEV;
	}

	struct flash_pages_info last;
	size_t pages = flash_get_page_count(flash_dev);

	if (pages == 0U || flash_get_page_info_by_idx(flash_dev, pages - 1U, &last) != 0) {
		LOG_ERR("Cannot read the flash page layout");
		return -EIO;
	}
	flash_size = (uint32_t)last.start_offset + (uint32_t)last.size;

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
}

/*
 * Collect the opcode/address/dummy bytes the BMC writes. Returns -ENOTSUP for
 * an opcode outside flash_ops[] or for data written after a complete header.
 */
static int flash_cmd_write(const uint8_t *payload, size_t payload_len)
{
	size_t copy_len;

	if (!spi_session_active) {
		return -ENOTSUP;
	}

	if (flash_session_op == NULL) {
		if (flash_session_hdr_len != 0U) {
			return -ENOTSUP;
		}

		flash_session_op = flash_op_find(payload[0]);
		if (flash_session_op == NULL) {
			LOG_WRN("Unsupported flash opcode 0x%02x", payload[0]);
			flash_session_hdr_len = 1U;
			return -ENOTSUP;
		}
	}

	if (flash_session_hdr_len >= flash_session_op->hdr_len) {
		return -ENOTSUP;
	}

	copy_len = MIN(payload_len, flash_session_op->hdr_len - flash_session_hdr_len);
	memcpy(&flash_session_hdr[flash_session_hdr_len], payload, copy_len);
	flash_session_hdr_len += copy_len;

	if (flash_session_hdr_len == flash_session_op->hdr_len) {
		flash_session_offset = 0;
		for (size_t i = 1; i <= flash_session_op->addr_len; i++) {
			flash_session_offset = (flash_session_offset << 8) | flash_session_hdr[i];
		}
	}

	return 0;
}

/* Serve a read for the latched opcode; consecutive reads continue the stream. */
static int flash_cmd_read(const struct device *spi_dev, uint32_t read_count,
			  uint8_t *resp_payload, size_t *resp_payload_len)
{
	const struct flash_op *op = flash_session_op;
	int ret = 0;

	if (!spi_session_active) {
		LOG_WRN("SPI read outside a CS-asserted session");
		return -EINVAL;
	}

	if (op == NULL) {
		return -ENOTSUP;
	}

	if (flash_session_hdr_len < op->hdr_len) {
		LOG_WRN("Flash opcode 0x%02x read before full header (%u/%u bytes)",
			op->opcode, (unsigned int)flash_session_hdr_len, op->hdr_len);
		return -EINVAL;
	}

	if (!flash_session_ready(spi_dev)) {
		return -ENODEV;
	}

	memset(resp_payload, 0, read_count);

	switch (op->kind) {
	case FLASH_OP_RDID: {
		uint8_t jedec_id[SPI_NOR_MAX_ID_LEN] = { 0 };

		/* A CS session may read the ID in pieces; bytes past it read as 0. */
		ret = flash_read_jedec_id(spi_dev, jedec_id);
		if (ret == 0 && flash_session_offset < sizeof(jedec_id)) {
			memcpy(resp_payload, &jedec_id[flash_session_offset],
			       MIN((size_t)read_count, sizeof(jedec_id) - flash_session_offset));
		}
		break;
	}

	case FLASH_OP_SFDP: {
		/* Serve what the cache holds; anything past it is read from the chip. */
		size_t cached = 0U;

		if (sfdp_cache_valid && flash_session_offset < SFDP_CACHE_SIZE) {
			cached = MIN((size_t)read_count,
				     SFDP_CACHE_SIZE - (size_t)flash_session_offset);
			memcpy(resp_payload, &sfdp_cache[flash_session_offset], cached);
		}
		if (cached < read_count) {
			ret = flash_sfdp_read(spi_dev, (off_t)(flash_session_offset + cached),
					      resp_payload + cached, read_count - cached);
		}
		break;
	}

	case FLASH_OP_READ:
		/* The address comes from the host: keep the whole read inside the chip. */
		if (flash_session_offset >= flash_size ||
		    read_count > flash_size - flash_session_offset) {
			LOG_ERR("Flash read 0x%08x+%u beyond 0x%08x", flash_session_offset,
				read_count, flash_size);
			return -EINVAL;
		}
		ret = flash_read(spi_dev, (off_t)flash_session_offset, resp_payload, read_count);
		break;
	}

	if (ret != 0) {
		LOG_ERR("Flash opcode 0x%02x at 0x%08x failed: %d", op->opcode,
			flash_session_offset, ret);
		return ret;
	}

	flash_session_offset += read_count;
	*resp_payload_len = read_count;
	return 0;
}

/*
 * Set on USB host reset (ISR context). The next request ends whatever CS
 * session the old host left open, so a new host's read without ASSERT cannot
 * continue the old opcode and offset.
 */
static atomic_t spi_host_reset_pending;

static void lstp_spi_host_reset(void)
{
	atomic_set(&spi_host_reset_pending, 1);
}

static lstp_status_t lstp_spi_receive(uint8_t channel_id,
				      struct lstp_hdr *hdr,
				      uint8_t *payload, size_t payload_len,
				      uint8_t *resp_payload, size_t *resp_payload_len,
				      bool *send_response)
{
	lstp_spi_command_t cmd =
		(lstp_spi_command_t)(hdr->cmd_status_code & LSTP_SPI_CMD_CODE_MASK);
	int ret = 0;

	if (atomic_cas(&spi_host_reset_pending, 1, 0)) {
		spi_end_session();
	}

	*resp_payload_len = 0;
	/* Posted writes have no reply; an extra untagged reply shifts later reads. */
	*send_response = cmd != LSTP_SPI_CMD_POSTED_WRITE;

	const struct device *spi_dev = get_spi_device(hdr->cmd_status_code);
	if (!spi_dev || !device_is_ready(spi_dev)) {
		LOG_ERR("SPI device not ready");
		ret = -ENODEV;
		goto out_deassert;
	}

	if (payload_len > LSTP_MAX_PAYLOAD_SIZE) {
		ret = -EMSGSIZE;
		goto out_deassert;
	}

	switch (cmd) {

	/* Pad the 4-byte speed with 8 zero bytes; the host driver expects a 12-byte response. */
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
		break;
	}

	case LSTP_SPI_CMD_WRITE:
	case LSTP_SPI_CMD_POSTED_WRITE: {
		if (spi_cmd_has_assert(hdr)) {
			spi_start_session();
		}

		if (payload_len > 0U) {
			ret = flash_cmd_write(payload, payload_len);
		}

		if (cmd == LSTP_SPI_CMD_WRITE && ret == 0) {
			resp_payload[0] = 0;
			*resp_payload_len = 1;
		}

		LOG_DBG("SPI Write: len=%zu ret=%d", payload_len, ret);
		break;
	}

	/* A response is one packet: return at most one payload; the host continues from there. */
	case LSTP_SPI_CMD_READ: {
		if (payload_len < 4) {
			ret = -EINVAL;
			break;
		}

		if (spi_cmd_has_assert(hdr)) {
			spi_start_session();
		}

		uint32_t read_count = spi_read_count_from_payload(payload);

		if (read_count > LSTP_MAX_PAYLOAD_SIZE) {
			read_count = LSTP_MAX_PAYLOAD_SIZE;
		}

		if (read_count == 0U) {
			*send_response = !spi_cmd_is_cs_only_read(hdr, payload, payload_len);
			LOG_DBG("SPI Read: zero-length %s", *send_response ? "with response" : "CS-only");
			break;
		}

		ret = flash_cmd_read(spi_dev, read_count, resp_payload, resp_payload_len);
		LOG_DBG("SPI Read: count=%u ret=%d", read_count, ret);
		break;
	}

	/* A full-duplex exchange would need the bus itself; the channel never drives it. */
	case LSTP_SPI_CMD_WRITE_READ:
		ret = -ENOTSUP;
		break;

	default:
		LOG_ERR("Unknown SPI command: 0x%02x", cmd);
		ret = -ENOTSUP;
		break;
	}

out_deassert:
	if (spi_cmd_has_deassert(hdr)) {
		spi_end_session();
	}

	return zephyr_ret_to_lstp(ret);
}

static lstp_status_t lstp_spi_read_config(const struct lstp_channel_config_read_request *req,
					  uint8_t *buf, size_t cap, size_t *len)
{
	struct lstp_spi_channel_config *spi_cfg = (struct lstp_spi_channel_config *)buf;

	ARG_UNUSED(req);

	if (sizeof(*spi_cfg) > cap) {
		return LSTP_STATUS_ERROR;
	}

	spi_cfg->channel_num_cs = LSTP_SPI_DEVICE_COUNT;
	spi_cfg->freq_hz = sys_cpu_to_le32(spi_speed_hz);
	*len = sizeof(*spi_cfg);
	return LSTP_STATUS_SUCCESS;
}

LSTP_CHANNEL_DEFINE(lstp_spi_channel,
	.id = LSTP_SPI_CHANNEL_ID,
	.type = LSTP_CHANNEL_TYPE_SPI,
	.name = LSTP_SPI_CHANNEL_NAME,
	.init = lstp_spi_init,
	.read_config = lstp_spi_read_config,
	.receive = lstp_spi_receive,
	.host_reset = lstp_spi_host_reset,
);
