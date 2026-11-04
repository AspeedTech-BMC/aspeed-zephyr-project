/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/espi.h>
#include <zephyr/drivers/espi_aspeed.h>
#include <zephyr/sys/byteorder.h>
#include <string.h>

#include "espi_bridge.h"
#include "safs_handler.h"

LOG_MODULE_REGISTER(safs_handler, CONFIG_LOG_DEFAULT_LEVEL);

#define SAFS_ERASE_4K        (4 * 1024)
#define SAFS_ERASE_64K       (64 * 1024)
#define SAFS_ERASE_128K      (128 * 1024)
#define SAFS_ERASE_256K      (256 * 1024)

static uint8_t safs_flash_buf[SAFS_FLASH_SIZE];
static uint8_t taf_tx_buf[sizeof(struct espi_flash_cmplt) + ESPI_PLD_LEN_MAX];
static K_MUTEX_DEFINE(safs_flash_lock);

int safs_flash_read(uint32_t offset, void *buf, size_t len)
{
	if (!buf) {
		return -EINVAL;
	}
	if (offset >= SAFS_FLASH_SIZE || len > SAFS_FLASH_SIZE - offset) {
		return -EINVAL;
	}

	k_mutex_lock(&safs_flash_lock, K_FOREVER);
	memcpy(buf, safs_flash_buf + offset, len);
	k_mutex_unlock(&safs_flash_lock);

	return 0;
}

int safs_flash_write(uint32_t offset, const void *buf, size_t len)
{
	if (!buf && len > 0) {
		return -EINVAL;
	}
	if (offset >= SAFS_FLASH_SIZE || len > SAFS_FLASH_SIZE - offset) {
		return -EINVAL;
	}

	k_mutex_lock(&safs_flash_lock, K_FOREVER);
	if (len > 0) {
		memcpy(safs_flash_buf + offset, buf, len);
	}
	k_mutex_unlock(&safs_flash_lock);

	return 0;
}

int safs_flash_erase(uint32_t offset, size_t len)
{
	if (offset >= SAFS_FLASH_SIZE || len > SAFS_FLASH_SIZE - offset) {
		return -EINVAL;
	}

	k_mutex_lock(&safs_flash_lock, K_FOREVER);
	memset(safs_flash_buf + offset, 0xff, len);
	k_mutex_unlock(&safs_flash_lock);

	return 0;
}

static bool safs_registered;

/* 0 until the TAF handler is registered, which hides the SAFS MMIO window. */
size_t safs_flash_get_size(void)
{
	return safs_registered ? SAFS_FLASH_SIZE : 0U;
}

static uint16_t taf_payload_len(uint16_t len)
{
	return len ? len : ESPI_PLD_LEN_MAX;
}

static bool taf_range_valid(uint32_t addr, uint32_t len)
{
	return (addr < SAFS_FLASH_SIZE) && (len <= SAFS_FLASH_SIZE - addr);
}

/* Erase-size code in the length field, as in CH3_CAP: 1=4K, 2=64K, 4=128K, 5=256K. */
static bool taf_erase_size(uint16_t type, uint32_t *erase_size)
{
	switch (type) {
	case 1:
		*erase_size = SAFS_ERASE_4K;
		return true;
	case 2:
		*erase_size = SAFS_ERASE_64K;
		return true;
	case 4:
		*erase_size = SAFS_ERASE_128K;
		return true;
	case 5:
		*erase_size = SAFS_ERASE_256K;
		return true;
	default:
		return false;
	}
}

/*
 * put_tx returns -EBUSY while the previous completion is still pending. The
 * driver calls the handler from espi_taf_work(), so sleeping is safe.
 * Retry for up to 5 ms before dropping the completion, which would leave
 * the host's TAF request (and BIOS) hanging.
 */
#define TAF_PUT_TX_RETRIES 50
#define TAF_PUT_TX_TIMEOUT_MS 5

static int taf_put_tx(const struct device *dev, struct espi_aspeed_ioc *ioc)
{
	int64_t deadline = k_uptime_get() + TAF_PUT_TX_TIMEOUT_MS;
	int ret;

	for (int i = 0; ; i++) {
		ret = espi_aspeed_flash_put_tx(dev, ioc);
		if (ret != -EBUSY || i >= TAF_PUT_TX_RETRIES ||
		    k_uptime_get() >= deadline) {
			return ret;
		}
		k_usleep(100);
	}
}

static void send_unsuc_cmplt(const struct device *dev, uint8_t tag)
{
	struct espi_flash_cmplt cmplt;
	struct espi_aspeed_ioc ioc;
	int ret;

	cmplt.cyc   = ESPI_FLASH_UNSUC_CMPLT;
	cmplt.tag   = tag;
	cmplt.len_h = 0;
	cmplt.len_l = 0;

	ioc.pkt_len = sizeof(cmplt);
	ioc.pkt     = (uint8_t *)&cmplt;
	ret = taf_put_tx(dev, &ioc);
	if (ret) {
		LOG_ERR("UNSUC_CMPLT put_tx failed: %d", ret);
	}
}

static void send_suc_cmplt(const struct device *dev, uint8_t tag, const char *op)
{
	struct espi_flash_cmplt cmplt;
	struct espi_aspeed_ioc ioc;
	int ret;

	cmplt.cyc   = ESPI_FLASH_SUC_CMPLT;
	cmplt.tag   = tag;
	cmplt.len_h = 0;
	cmplt.len_l = 0;

	ioc.pkt_len = sizeof(cmplt);
	ioc.pkt     = (uint8_t *)&cmplt;
	ret = taf_put_tx(dev, &ioc);
	if (ret) {
		LOG_ERR("TAF %s completion failed: %d", op, ret);
	}
}

static void espi_taf_handler(const struct device *dev, struct espi_taf_req *req, void *user_data)
{
	struct espi_aspeed_ioc ioc;
	int ret;

	ARG_UNUSED(user_data);

	LOG_DBG("TAF request: dev=%s cyc=0x%02x tag=0x%02x len=%u addr=0x%08x",
		dev->name, req->cyc, req->tag, req->len, req->addr);

	switch (req->cyc) {
	case ESPI_FLASH_READ: {
		struct espi_flash_cmplt *cmplt = (struct espi_flash_cmplt *)taf_tx_buf;
		uint16_t len = taf_payload_len(req->len);

		if (!taf_range_valid(req->addr, len)) {
			LOG_ERR("TAF READ out of range: addr=0x%08x len=%u", req->addr, len);
			send_unsuc_cmplt(dev, req->tag);
			return;
		}

		cmplt->cyc   = ESPI_FLASH_SUC_CMPLT_D_ONLY;
		cmplt->tag   = req->tag;
		cmplt->len_h = len >> 8;
		cmplt->len_l = len & 0xff;

		if (safs_flash_read(req->addr, cmplt->data, len) != 0) {
			send_unsuc_cmplt(dev, req->tag);
			return;
		}

		LOG_DBG("[TAF READ] addr=0x%08x len=%u data[0]=0x%02x",
			req->addr, len, cmplt->data[0]);

		ioc.pkt     = taf_tx_buf;
		ioc.pkt_len = sizeof(*cmplt) + len;
		ret = taf_put_tx(dev, &ioc);
		if (ret) {
			LOG_ERR("TAF READ completion failed: %d", ret);
		}
		break;
	}
	case ESPI_FLASH_WRITE: {
		uint16_t len = taf_payload_len(req->len);

		if (!req->data || !taf_range_valid(req->addr, len)) {
			LOG_ERR("TAF WRITE invalid parameters: addr=0x%08x len=%u", req->addr, len);
			send_unsuc_cmplt(dev, req->tag);
			return;
		}

		if (safs_flash_write(req->addr, req->data, len) != 0) {
			send_unsuc_cmplt(dev, req->tag);
			return;
		}
		send_suc_cmplt(dev, req->tag, "WRITE");
		break;
	}
	case ESPI_FLASH_ERASE: {
		uint32_t erase_size;

		if (!taf_erase_size(req->len, &erase_size) ||
		    (req->addr % erase_size) != 0 ||
		    !taf_range_valid(req->addr, erase_size)) {
			LOG_ERR("TAF ERASE invalid parameters: addr=0x%08x type=%u", req->addr, req->len);
			send_unsuc_cmplt(dev, req->tag);
			return;
		}

		if (safs_flash_erase(req->addr, erase_size) != 0) {
			send_unsuc_cmplt(dev, req->tag);
			return;
		}
		send_suc_cmplt(dev, req->tag, "ERASE");
		break;
	}
	default:
		LOG_ERR("TAF unknown cycle: cyc=0x%02x tag=0x%02x", req->cyc, req->tag);
		send_unsuc_cmplt(dev, req->tag);
		break;
	}
}

int safs_init(void)
{
	const struct device *dev = DEVICE_DT_GET(ESPI_NODE);
	int ret;

	memset(safs_flash_buf, 0xff, sizeof(safs_flash_buf));

	LOG_INF("SAFS init: registering MMIO-backed TAF handler on %s", dev->name);

	ret = espi_aspeed_taf_register(dev, espi_taf_handler, NULL);
	if (ret) {
		LOG_ERR("SAFS init: TAF handler register failed: %d", ret);
		return ret;
	}

	safs_registered = true;
	LOG_INF("SAFS init: MMIO-backed TAF handler registered (size=%u)", SAFS_FLASH_SIZE);
	return 0;
}
