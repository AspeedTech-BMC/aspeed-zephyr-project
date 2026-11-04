/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/reboot.h>
#include <string.h>

#include "lstp/lstp_common.h"
#include "lstp/lstp_backend.h"
#include "lstp/lstp_channel.h"
#include "gpio/lstp_gpio.h"
#include "uart/lstp_uart.h"
#include "lstp/lstp_usb.h"
#include "espi_bridge.h"
#include "espi_oob_bridge.h"
#include "safs_handler.h"

LOG_MODULE_REGISTER(lstp_mmio, CONFIG_LOG_DEFAULT_LEVEL);

#define SAFS_MMIO_OFFSET_BASE 0x10000U /* 64KB: 0..64KB for Port 80 / perif_mem, >=64KB for SAFS Flash */
/* An empty WRITE here cold-reboots the AST1040 when CONFIG_OBMF_ESPI_MMIO_RESET=y.
 * There is no authorization: any USB host that can talk LSTP may trigger it.
 */
#define LSTP_MMIO_RESET_OFFSET 0xFFFFFFFCU

static struct k_work_delayable mmio_reset_work;

enum mmio_access {
	MMIO_ACCESS_RO,
	MMIO_ACCESS_RW,
	MMIO_ACCESS_W1C,
};

struct mmio_region {
	uint32_t start;
	uint32_t end; /* exclusive */
	enum mmio_access access;
};

static const struct mmio_region perif_regions[] = {
	{ 0x0000U, ESPI_VWIRE_OUT_OFFSET, MMIO_ACCESS_RO },
	{ ESPI_VWIRE_OUT_OFFSET, ESPI_VWIRE_OUT_OFFSET + 4U, MMIO_ACCESS_RW },
	{ ESPI_VWIRE_OUT_OFFSET + 4U, ESPI_OOB_RX_STATUS_OFFSET, MMIO_ACCESS_RO },
	{ ESPI_OOB_RX_STATUS_OFFSET, ESPI_OOB_RX_STATUS_OFFSET + 1U, MMIO_ACCESS_W1C },
	{ ESPI_OOB_RX_STATUS_OFFSET + 1U, ESPI_OOB_TX_CTRL_OFFSET, MMIO_ACCESS_RO },
	{ ESPI_OOB_TX_CTRL_OFFSET, ESPI_OOB_TX_DATA_OFFSET + ESPI_OOB_TX_DATA_SIZE,
	  MMIO_ACCESS_RW },
	{ ESPI_OOB_TX_DATA_OFFSET + ESPI_OOB_TX_DATA_SIZE, 0x10000U, MMIO_ACCESS_RO },
};

static const struct mmio_region *find_perif_region(uint32_t offset, size_t len)
{
	uint32_t end;

	if (len == 0U || offset > UINT32_MAX - len) {
		return NULL;
	}
	end = offset + len;
	for (size_t i = 0; i < ARRAY_SIZE(perif_regions); i++) {
		if (offset >= perif_regions[i].start && end <= perif_regions[i].end) {
			return &perif_regions[i];
		}
	}
	return NULL;
}

static void write_diag_u32(uint32_t offset, uint32_t value)
{
	value = sys_cpu_to_le32(value);
	(void)espi_perif_mem_write(offset, &value, sizeof(value));
}

static void refresh_diagnostics(void)
{
	struct lstp_uart_stats uart;
	struct lstp_usb_stats usb;

	lstp_uart_get_stats(&uart);
	lstp_usb_get_stats(&usb);
	write_diag_u32(ESPI_DIAG_UART_RX_DROP_OFFSET, uart.rx_dropped_bytes);
	write_diag_u32(ESPI_DIAG_UART_TX_DROP_OFFSET, uart.tx_dropped_bytes);
	write_diag_u32(ESPI_DIAG_USB_RESP_DROP_OFFSET, usb.response_drops);
	write_diag_u32(ESPI_DIAG_USB_EVT_DROP_OFFSET, usb.event_drops);
	write_diag_u32(ESPI_DIAG_USB_RX_DROP_OFFSET, usb.rx_drops);
	write_diag_u32(ESPI_DIAG_USB_ERROR_OFFSET, usb.write_errors);
	write_diag_u32(ESPI_DIAG_USB_HIGH_WATER_OFF, usb.tx_high_water);
	/* Unsolicited events are best-effort; reserved RETRY counters remain zero. */
	write_diag_u32(ESPI_DIAG_UART_DROP_OFFSET, uart.rx_forward_dropped_bytes);
	if (IS_ENABLED(CONFIG_OBMF_LSTP_GPIO_CHANNEL)) {
		write_diag_u32(ESPI_DIAG_GPIO_DROP_OFFSET, lstp_gpio_get_event_drops());
		write_diag_u32(ESPI_DIAG_GPIO_QUEUE_DROP_OFF, lstp_gpio_get_irq_drops());
	} else {
		write_diag_u32(ESPI_DIAG_GPIO_DROP_OFFSET, 0U);
		write_diag_u32(ESPI_DIAG_GPIO_QUEUE_DROP_OFF, 0U);
	}
}

static int perif_mmio_write(uint32_t offset, const uint8_t *data, size_t len)
{
	const struct mmio_region *region = find_perif_region(offset, len);
	int rc;

	if (region == NULL || region->access == MMIO_ACCESS_RO) {
		return -EACCES;
	}
	if (offset >= ESPI_OOB_RX_STATUS_OFFSET && offset < ESPI_OOB_MAILBOX_END) {
		return espi_oob_bridge_mmio_write(offset, data, len);
	}
	if (offset <= ESPI_VWIRE_OUT_OFFSET + 3U && offset + len > ESPI_VWIRE_OUT_OFFSET) {
		/* Under the vwire lock, so a mirror sync cannot overwrite the new value. */
		return espi_vwire_write_output_mirror(offset, data, len);
	}
	rc = espi_perif_mem_write(offset, data, len);
	return rc;
}

static void mmio_reset_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	/* Only scheduled when CONFIG_OBMF_ESPI_MMIO_RESET (which selects REBOOT). */
	if (IS_ENABLED(CONFIG_OBMF_ESPI_MMIO_RESET)) {
		LOG_INF("MMIO reset: triggering cold reboot");
		sys_reboot(SYS_REBOOT_COLD);
	}
}

static int lstp_mmio_init(void)
{
	k_work_init_delayable(&mmio_reset_work, mmio_reset_work_handler);
	LOG_INF("LSTP MMIO channel initialized");
	return 0;
}

static lstp_status_t lstp_mmio_receive(uint8_t channel_id,
				       struct lstp_hdr *hdr,
				       uint8_t *payload, size_t payload_len,
				       uint8_t *resp_payload, size_t *resp_payload_len,
				       bool *send_response)
{
	ARG_UNUSED(channel_id);
	ARG_UNUSED(send_response);
	*resp_payload_len = 0;

	if (!hdr) {
		return LSTP_STATUS_ERROR;
	}

	uint8_t cmd = hdr->cmd_status_code & ~LSTP_RESPONSE_BIT;

	switch (cmd) {
	case LSTP_MMIO_CMD_READ: {
		if (payload_len < sizeof(struct lstp_mmio_read_request)) {
			LOG_ERR("MMIO READ payload too small: %zu", payload_len);
			return LSTP_STATUS_ERROR;
		}

		struct lstp_mmio_read_request *req =
			(struct lstp_mmio_read_request *)payload;
		uint32_t offset = sys_le32_to_cpu(req->offset);
		uint16_t length = sys_le16_to_cpu(req->length);

		if (length > LSTP_MAX_PAYLOAD_SIZE) {
			LOG_ERR("MMIO READ requested length too large: %u", length);
			return LSTP_STATUS_ERROR;
		}

		if (offset >= SAFS_MMIO_OFFSET_BASE) {
			uint32_t flash_off = offset - SAFS_MMIO_OFFSET_BASE;
			size_t flash_sz = safs_flash_get_size();

			if (flash_off > flash_sz || length > flash_sz - flash_off) {
				return LSTP_STATUS_ERROR;
			}
			if (length == 0U) {
				return LSTP_STATUS_SUCCESS;
			}

			int ret = safs_flash_read(flash_off, resp_payload, length);
			if (ret != 0) {
				LOG_ERR("SAFS Flash READ failed at offset 0x%08x len %u (ret=%d)",
					flash_off, length, ret);
				return LSTP_STATUS_ERROR;
			}

			*resp_payload_len = length;
			return LSTP_STATUS_SUCCESS;
		} else {
			size_t mem_size = espi_perif_mem_get_size();
			if (offset > mem_size || length > mem_size - offset) {
				return LSTP_STATUS_ERROR;
			}
			if (length == 0U) {
				return LSTP_STATUS_SUCCESS;
			}
			if (offset < ESPI_DIAG_UART_RX_DROP_OFFSET) {
				espi_vwire_sync_all_to_mmio();
			}
			refresh_diagnostics();

			int ret = espi_perif_mem_read(offset, resp_payload, length);
			if (ret != 0) {
				LOG_ERR("MMIO READ failed at offset 0x%08x len %u (ret=%d)",
					offset, length, ret);
				return LSTP_STATUS_ERROR;
			}

			*resp_payload_len = length;
			return LSTP_STATUS_SUCCESS;
		}
	}

	case LSTP_MMIO_CMD_WRITE: {
		if (payload_len < sizeof(uint32_t)) {
			LOG_ERR("MMIO WRITE payload too small: %zu", payload_len);
			return LSTP_STATUS_ERROR;
		}

		uint32_t offset = sys_get_le32(payload);
		size_t data_len = payload_len - sizeof(uint32_t);

		if (data_len == 0) {
			if (offset == LSTP_MMIO_RESET_OFFSET) {
				if (!IS_ENABLED(CONFIG_OBMF_ESPI_MMIO_RESET)) {
					LOG_WRN("MMIO reset request rejected (OBMF_ESPI_MMIO_RESET=n)");
					return LSTP_STATUS_NOT_SUPPORTED;
				}
				LOG_INF("MMIO reset requested by host (unauthenticated)");
				k_work_schedule(&mmio_reset_work, K_MSEC(10));
				*resp_payload_len = 0;
				return LSTP_STATUS_SUCCESS;
			}
			/* An empty write anywhere else is malformed, not a no-op. */
			return LSTP_STATUS_ERROR;
		}

		if (offset >= SAFS_MMIO_OFFSET_BASE) {
			uint32_t flash_off = offset - SAFS_MMIO_OFFSET_BASE;
			size_t flash_sz = safs_flash_get_size();

			if (!IS_ENABLED(CONFIG_OBMF_ESPI_MMIO_SAFS_WRITE)) {
				LOG_WRN("SAFS write rejected (OBMF_ESPI_MMIO_SAFS_WRITE=n)");
				return LSTP_STATUS_NOT_SUPPORTED;
			}
			if (flash_off > flash_sz || data_len > flash_sz - flash_off) {
				return LSTP_STATUS_ERROR;
			}
			int ret = safs_flash_write(flash_off, payload + sizeof(uint32_t), data_len);

			if (ret != 0) {
				LOG_ERR("SAFS Flash WRITE failed at offset 0x%08x len %zu (ret=%d)",
					flash_off, data_len, ret);
				return LSTP_STATUS_ERROR;
			}
		} else {
			int ret = perif_mmio_write(offset, payload + sizeof(uint32_t), data_len);

			if (ret != 0) {
				LOG_ERR("MMIO WRITE failed at offset 0x%08x len %zu (ret=%d)",
					offset, data_len, ret);
				return LSTP_STATUS_ERROR;
			}
		}

		*resp_payload_len = 0;
		return LSTP_STATUS_SUCCESS;
	}

	default:
		LOG_WRN("Unknown MMIO command: 0x%02x", cmd);
		return LSTP_STATUS_NOT_SUPPORTED;
	}
}

static lstp_status_t lstp_mmio_read_config(const struct lstp_channel_config_read_request *req,
					   uint8_t *buf, size_t cap, size_t *len)
{
	struct lstp_mmio_channel_config *mmio_cfg = (struct lstp_mmio_channel_config *)buf;

	ARG_UNUSED(req);

	*len = 0;
	if (sizeof(*mmio_cfg) <= cap) {
		mmio_cfg->base_addr = sys_cpu_to_le32(espi_perif_mem_get_base_addr());
		mmio_cfg->size = sys_cpu_to_le32(SAFS_MMIO_OFFSET_BASE + safs_flash_get_size());
		*len = sizeof(*mmio_cfg);
	}
	return LSTP_STATUS_SUCCESS;
}

/* eSPI peripheral memory window plus the SAFS flash behind it. */
LSTP_CHANNEL_DEFINE(lstp_mmio_channel,
	.id = LSTP_MMIO_CHANNEL_ID,
	.type = LSTP_CHANNEL_TYPE_MMIO,
	.name = "ESPI_MEM",
	.init = lstp_mmio_init,
	.read_config = lstp_mmio_read_config,
	.receive = lstp_mmio_receive,
);
