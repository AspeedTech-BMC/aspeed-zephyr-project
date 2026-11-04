/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>
#include <zephyr/drivers/espi.h>
#include <zephyr/drivers/espi_aspeed.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>

#include "espi_oob_bridge.h"

LOG_MODULE_REGISTER(espi_oob_bridge, CONFIG_LOG_DEFAULT_LEVEL);

int espi_ast2700_oob_get_rx(const struct device *dev, struct espi_aspeed_ioc *ioc,
			    bool blocking);
int espi_ast2700_oob_put_tx(const struct device *dev, struct espi_aspeed_ioc *ioc);

static const struct device *oob_dev;
static struct k_mutex oob_lock;
static struct k_work oob_rx_work;
static struct k_sem oob_rx_events;
static struct espi_callback oob_rx_cb;

static uint8_t rx_packet[sizeof(struct espi_comm_hdr) + ESPI_PLD_LEN_MAX];
static uint8_t tx_packet[sizeof(struct espi_comm_hdr) + ESPI_PLD_LEN_MAX];
static uint8_t echo_payload[ESPI_PLD_LEN_MAX];
static uint16_t echo_len;
static uint8_t echo_tag;
static bool echo_pending;
static uint32_t rx_count;
static uint32_t tx_count;

static void write_u32(uint32_t offset, uint32_t value)
{
	value = sys_cpu_to_le32(value);
	(void)espi_perif_mem_write(offset, &value, sizeof(value));
}

static uint8_t read_ctrl(void)
{
	uint8_t ctrl = 0;

	(void)espi_perif_mem_read(ESPI_OOB_TX_CTRL_OFFSET, &ctrl, sizeof(ctrl));
	return ctrl;
}

static void write_ctrl(uint8_t ctrl)
{
	(void)espi_perif_mem_write(ESPI_OOB_TX_CTRL_OFFSET, &ctrl, sizeof(ctrl));
}

static int send_raw_locked(uint8_t tag, const uint8_t *data, uint16_t len)
{
	struct espi_comm_hdr *hdr = (struct espi_comm_hdr *)tx_packet;
	struct espi_aspeed_ioc ioc = {
		.pkt = tx_packet,
		.pkt_len = sizeof(*hdr) + len,
	};
	int rc;

	if (len == 0U || len > ESPI_PLD_LEN_MAX || data == NULL) {
		return -EINVAL;
	}

	hdr->cyc = ESPI_OOB_MSG;
	hdr->tag = tag & 0x0fU;
	hdr->len_h = (len >> 8) & 0x0fU;
	hdr->len_l = len & 0xffU;
	memcpy(hdr + 1, data, len);

	rc = espi_ast2700_oob_put_tx(oob_dev, &ioc);
	if (rc == 0) {
		tx_count++;
		write_u32(ESPI_OOB_TX_PKT_CNT_OFFSET, tx_count);
	}

	return rc;
}

static int try_mailbox_tx_locked(void)
{
	uint8_t ctrl = read_ctrl();
	uint8_t tag;
	uint16_t len_le;
	uint16_t len;
	uint8_t data[ESPI_OOB_TX_DATA_SIZE];
	int rc;

	if ((ctrl & ESPI_OOB_CTRL_TRIGGER) == 0U) {
		return 0;
	}

	ctrl |= ESPI_OOB_CTRL_BUSY;
	write_ctrl(ctrl);
	(void)espi_perif_mem_read(ESPI_OOB_TX_TAG_OFFSET, &tag, sizeof(tag));
	(void)espi_perif_mem_read(ESPI_OOB_TX_LEN_OFFSET, &len_le, sizeof(len_le));
	len = sys_le16_to_cpu(len_le);
	if (len == 0U || len > sizeof(data)) {
		LOG_ERR("Invalid OOB mailbox TX length: %u", len);
		write_ctrl(ctrl & ~(ESPI_OOB_CTRL_TRIGGER | ESPI_OOB_CTRL_BUSY));
		return -EINVAL;
	}

	(void)espi_perif_mem_read(ESPI_OOB_TX_DATA_OFFSET, data, len);
	rc = send_raw_locked(tag, data, len);
	if (rc != -EBUSY) {
		write_ctrl(ctrl & ~(ESPI_OOB_CTRL_TRIGGER | ESPI_OOB_CTRL_BUSY));
		if (rc != 0) {
			LOG_ERR("OOB mailbox TX failed: %d", rc);
		}
	}

	return rc;
}

static void service_locked(void)
{
	int rc = try_mailbox_tx_locked();

	if (rc == -EBUSY || (read_ctrl() & ESPI_OOB_CTRL_TRIGGER) != 0U || !echo_pending) {
		return;
	}

	rc = send_raw_locked(echo_tag, echo_payload, echo_len);
	if (rc != -EBUSY) {
		if (rc != 0) {
			LOG_ERR("OOB echo failed: %d", rc);
		}
		echo_pending = false;
	}
}

static void publish_rx_locked(const struct espi_comm_hdr *hdr, uint16_t len)
{
	uint8_t status = 0;
	uint8_t tag = hdr->tag;
	uint16_t captured_len = MIN(len, ESPI_OOB_RX_DATA_SIZE);
	/* RX_LEN is the byte count in the data window; OVERRUN flags a truncation. */
	uint16_t len_le = sys_cpu_to_le16(captured_len);

	rx_count++;
	write_u32(ESPI_OOB_RX_PKT_CNT_OFFSET, rx_count);
	(void)espi_perif_mem_read(ESPI_OOB_RX_STATUS_OFFSET, &status, sizeof(status));
	/* Until a reader acks READY, later packets are counted as overruns and dropped. */
	if ((status & ESPI_OOB_STATUS_READY) != 0U) {
		status |= ESPI_OOB_STATUS_OVERRUN;
		(void)espi_perif_mem_write(ESPI_OOB_RX_STATUS_OFFSET, &status, sizeof(status));
		return;
	}

	(void)espi_perif_mem_write(ESPI_OOB_RX_TAG_OFFSET, &tag, sizeof(tag));
	(void)espi_perif_mem_write(ESPI_OOB_RX_LEN_OFFSET, &len_le, sizeof(len_le));
	(void)espi_perif_mem_write(ESPI_OOB_RX_DATA_OFFSET, hdr + 1, captured_len);
	status = (status & ESPI_OOB_STATUS_OVERRUN) | ESPI_OOB_STATUS_READY;
	if (captured_len != len) {
		status |= ESPI_OOB_STATUS_OVERRUN;
	}
	(void)espi_perif_mem_write(ESPI_OOB_RX_STATUS_OFFSET, &status, sizeof(status));
}

static void oob_rx_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	while (k_sem_take(&oob_rx_events, K_NO_WAIT) == 0) {
		struct espi_aspeed_ioc ioc = {
			.pkt = rx_packet,
			.pkt_len = sizeof(rx_packet),
		};
		struct espi_comm_hdr *hdr = (struct espi_comm_hdr *)rx_packet;
		uint16_t len;
		int rc;

		k_mutex_lock(&oob_lock, K_FOREVER);
		rc = espi_ast2700_oob_get_rx(oob_dev, &ioc, false);
		if (rc != 0) {
			k_mutex_unlock(&oob_lock);
			LOG_ERR("OOB RX failed: %d", rc);
			continue;
		}

		len = ((uint16_t)hdr->len_h << 8) | hdr->len_l;
		if (len == 0U) {
			len = ESPI_PLD_LEN_MAX;
		}
		if (hdr->cyc != ESPI_OOB_MSG || ioc.pkt_len != sizeof(*hdr) + len) {
			k_mutex_unlock(&oob_lock);
			LOG_ERR("Malformed OOB RX: cyc=0x%02x len=%u pkt=%u",
				hdr->cyc, len, ioc.pkt_len);
			continue;
		}

		publish_rx_locked(hdr, len);
		if ((read_ctrl() & ESPI_OOB_CTRL_ECHO_EN) != 0U) {
			if (echo_pending) {
				LOG_WRN("Dropping OOB echo while previous echo is pending");
			} else {
				echo_tag = hdr->tag;
				echo_len = len;
				memcpy(echo_payload, hdr + 1, len);
				echo_pending = true;
			}
		}
		service_locked();
		k_mutex_unlock(&oob_lock);
	}
}

static void oob_rx_handler(const struct device *dev, struct espi_callback *cb,
			   struct espi_event event)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(cb);
	ARG_UNUSED(event);

	k_sem_give(&oob_rx_events);
	k_work_submit_to_queue(espi_bridge_work_queue(), &oob_rx_work);
}

int espi_oob_bridge_init(const struct device *dev)
{
	uint8_t status = 0;
	/* Echo is a bring-up loopback; the BMC enables it through TX_CTRL when wanted. */
	uint8_t ctrl = 0U;
	int rc;

	if (!device_is_ready(dev)) {
		return -ENODEV;
	}

	oob_dev = dev;
	rx_count = 0;
	tx_count = 0;
	echo_pending = false;
	k_mutex_init(&oob_lock);
	k_sem_init(&oob_rx_events, 0, UINT_MAX);
	k_work_init(&oob_rx_work, oob_rx_work_handler);
	(void)espi_perif_mem_write(ESPI_OOB_RX_STATUS_OFFSET, &status, sizeof(status));
	(void)espi_perif_mem_write(ESPI_OOB_TX_CTRL_OFFSET, &ctrl, sizeof(ctrl));
	write_u32(ESPI_OOB_RX_PKT_CNT_OFFSET, 0);
	write_u32(ESPI_OOB_TX_PKT_CNT_OFFSET, 0);

	espi_init_callback(&oob_rx_cb, oob_rx_handler, ESPI_BUS_EVENT_OOB_RECEIVED);
	rc = espi_add_callback(oob_dev, &oob_rx_cb);
	if (rc != 0) {
		oob_dev = NULL;
		return rc;
	}

	LOG_INF("OOB bridge initialized");
	return 0;
}

void espi_oob_bridge_service(void)
{
	if (oob_dev == NULL) {
		return;
	}

	k_mutex_lock(&oob_lock, K_FOREVER);
	service_locked();
	k_mutex_unlock(&oob_lock);
}

int espi_oob_bridge_mmio_write(uint32_t offset, const uint8_t *data, size_t len)
{
	uint32_t end;
	int rc = 0;

	if (data == NULL || len == 0U || oob_dev == NULL ||
	    offset > UINT32_MAX - len) {
		return -EINVAL;
	}
	end = offset + len;
	if (offset < ESPI_OOB_RX_STATUS_OFFSET || end > ESPI_OOB_MAILBOX_END) {
		return -ERANGE;
	}

	k_mutex_lock(&oob_lock, K_FOREVER);
	if (offset == ESPI_OOB_RX_STATUS_OFFSET && len == 1U) {
		uint8_t status;

		(void)espi_perif_mem_read(offset, &status, sizeof(status));
		status &= ~(data[0] & (ESPI_OOB_STATUS_READY | ESPI_OOB_STATUS_OVERRUN));
		rc = espi_perif_mem_write(offset, &status, sizeof(status));
	} else if (offset >= ESPI_OOB_TX_CTRL_OFFSET &&
		   end <= ESPI_OOB_TX_DATA_OFFSET + ESPI_OOB_TX_DATA_SIZE) {
		uint8_t old_ctrl = read_ctrl();

		if ((old_ctrl & ESPI_OOB_CTRL_BUSY) != 0U &&
		    (offset != ESPI_OOB_TX_CTRL_OFFSET || len != 1U)) {
			rc = -EBUSY;
			goto unlock;
		}
		if (offset == ESPI_OOB_TX_CTRL_OFFSET) {
			uint8_t new_ctrl = (data[0] & (ESPI_OOB_CTRL_TRIGGER |
						       ESPI_OOB_CTRL_ECHO_EN)) |
					   (old_ctrl & ESPI_OOB_CTRL_BUSY);

			if ((old_ctrl & ESPI_OOB_CTRL_BUSY) != 0U) {
				new_ctrl |= old_ctrl & ESPI_OOB_CTRL_TRIGGER;
			}

			rc = espi_perif_mem_write(offset, &new_ctrl, sizeof(new_ctrl));
			if (rc == 0 && len > 1U) {
				rc = espi_perif_mem_write(offset + 1U, data + 1U, len - 1U);
			}
		} else {
			rc = espi_perif_mem_write(offset, data, len);
		}
		if (rc == 0) {
			service_locked();
		}
	} else {
		rc = -EACCES;
	}
unlock:
	k_mutex_unlock(&oob_lock);
	return rc;
}
