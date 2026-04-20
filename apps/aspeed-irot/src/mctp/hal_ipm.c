/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/ipm.h>

#include <zephyr/shell/shell.h>

#include <mctp_ipc.h>
#include <mctp.h>

LOG_MODULE_REGISTER(ipm_app, LOG_LEVEL_INF);

// TODO: Move to device tree
uint8_t *tx_mmio = (uint8_t *)0x5580000; // TX to PSP 431280000
uint8_t *rx_mmio = (uint8_t *)0x5480000; // RX from PSP 431080000

static void ipm_cb(const struct device *ipmdev, void *user_data,
		uint32_t id, volatile void *data)
{
	// int max_data_size = ipm_max_data_size_get(ipmdev);
	struct mctp_ipc_hdr *ipc_hdr = (struct mctp_ipc_hdr *)data;

	LOG_DBG("IN dev %s msg id %x, msg hdr = %08x len = %d", ipmdev->name, id, *(uint32_t *)data, ipc_hdr->msg_len);

	mctp_ipc_packet pkt;
	memcpy(&pkt.ipc_hdr, (void *)data, sizeof(pkt.ipc_hdr));
	memcpy(&pkt.hdr, rx_mmio, 4);
	pkt.buf = rx_mmio + 4;


	LOG_HEXDUMP_DBG(&pkt, 12, "IPC RECV");
	LOG_HEXDUMP_DBG(pkt.buf, 32, "IPC MEM BUF");
	
	int ret = mctp_ipc_send_raw(&pkt);
	if (ret != 0) {
		LOG_ERR("mctp_ipc_send_raw failed, ret=%d", ret);
	}
}

void ipm_mctp_main(void *a, void *b, void *c)
{
	const struct device *ipmdev = device_get_binding("ipc0@200");
	if (!ipmdev) {
		LOG_ERR("Failed to get binding for ipc0@200");
		return;
	}

	mctp_ipc_packet *pkt = malloc(sizeof(mctp_ipc_packet));
	int ret;

	while (1) {
		ret = mctp_ipc_recv(pkt);
		int send_len = 0;
		if (ret == 0) {
			
			LOG_DBG("OUT dev %s msg len %x, msg data at %p", ipmdev->name, pkt->ipc_hdr.msg_len, (void *)pkt);
			memcpy((void *)tx_mmio, &pkt->hdr, 4);
			memcpy((void *)(tx_mmio + 4), pkt->buf, pkt->ipc_hdr.msg_len - 4);
			send_len = sizeof(pkt->ipc_hdr);
			LOG_HEXDUMP_DBG(pkt, 12, "IPC SEND");
			LOG_HEXDUMP_DBG(pkt->buf, 32, "IPC MEM BUF");
			ipm_send(ipmdev, 5, 0, pkt, send_len);

			// Clear resude
			free(pkt->buf);
		}
	}
}

K_THREAD_DEFINE(ipm_mctp_tid, 1024, ipm_mctp_main, NULL, NULL, NULL, 5, 0, 0);

int ipm_init()
{
	int rc = 0;
	const struct device *ipmdev;
	int device_id, enable;

	LOG_INF("SSP IPM INIT");
	ipmdev = device_get_binding("ipc0@0");
	if (!ipmdev) {
		LOG_ERR("%s: device_get_binding failed to find device", "ipc0@0");
		rc = 1;
		goto fail;
	}

	device_id = 0;
	enable = 1;
	ipm_register_id_callback(ipmdev, device_id, ipm_cb, NULL);
	rc = ipm_set_id_enabled(ipmdev, device_id, enable);
	if (rc) {
		LOG_ERR("%s: cannot ipm_set_enabled", "ipc0@0");
		goto fail;
	}

	ipmdev = device_get_binding("ipc0@200");
	if (!ipmdev) {
		LOG_ERR("%s: device_get_binding failed to find device", "ipc0@200");
		rc = 1;
		goto fail;
	}

	device_id = 0;
	enable = 1;
	ipm_register_id_callback(ipmdev, device_id, ipm_cb, NULL);
	rc = ipm_set_id_enabled(ipmdev, device_id, enable);
	if (rc) {
		LOG_ERR("%s: cannot ipm_set_enabled", "ipc0@200");
		goto fail;
	}

	LOG_INF("All IPMs initialized");
fail:
	return 0;
}

SYS_INIT(ipm_init, APPLICATION, 1);
