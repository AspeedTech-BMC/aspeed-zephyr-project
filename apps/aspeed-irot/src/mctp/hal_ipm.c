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
#include <zephyr/drivers/ipm_ast.h>

#include <zephyr/shell/shell.h>

#include <mctp_ipc.h>
#include <mctp.h>

LOG_MODULE_REGISTER(ipm_app, LOG_LEVEL_INF);

#define IPM_MCTP_CHANNEL 0

static void ipm_cb(const struct device *ipmdev, void *user_data,
		uint32_t id, volatile void *data)
{
	struct mctp_ipc_hdr *ipc_hdr = (struct mctp_ipc_hdr *)data;
	void *hdr_ptr;
	int ret;
	mctp_ipc_packet pkt = {0};

	LOG_DBG("IN dev %s msg id %x, msg hdr = %08x len = %d", ipmdev->name, id, *(uint32_t *)data, ipc_hdr->msg_len);

	if (ipc_hdr->msg_len <= sizeof(mctp_hdr)) {
		LOG_ERR("Invalid RX frame length %u", ipc_hdr->msg_len);
		return;
	}

	memcpy(&pkt.ipc_hdr, (void *)data, sizeof(pkt.ipc_hdr));

	ret = ast_ipm_shmem_read(ipmdev, IPM_MCTP_CHANNEL, 0, &hdr_ptr, sizeof(pkt.hdr));
	if (ret < 0) {
		LOG_ERR("ast_ipm_shmem_read header failed, ret=%d", ret);
		return;
	}
	memcpy(&pkt.hdr, hdr_ptr, sizeof(pkt.hdr));

	ret = ast_ipm_shmem_read(ipmdev, IPM_MCTP_CHANNEL, sizeof(pkt.hdr), (void **)&pkt.buf,
				 ipc_hdr->msg_len - sizeof(pkt.hdr));
	if (ret < 0) {
		LOG_ERR("ast_ipm_shmem_read payload failed, ret=%d", ret);
		return;
	}

	LOG_HEXDUMP_DBG(&pkt.ipc_hdr, sizeof(pkt.ipc_hdr), "IPC RECV HEADER");
	LOG_HEXDUMP_DBG(&pkt.hdr, sizeof(pkt.hdr), "MCTP RECV HEADER");

	ret = mctp_ipc_send_raw(&pkt);
	if (ret != 0)
		LOG_ERR("mctp_ipc_send_raw failed, ret=%d", ret);
}

void ipm_mctp_main(void *a, void *b, void *c)
{
	const struct device *ipmdev = device_get_binding("ipc0@200");

	if (!ipmdev) {
		LOG_ERR("Failed to get binding for ipc0@200");
		return;
	}

	mctp_ipc_packet pkt = { 0 };
	int ret;

	while (1) {
		ret = mctp_ipc_recv(&pkt);
		if (ret == 0) {
			uint16_t payload_len;
			int send_len;

			if (!pkt.buf || pkt.ipc_hdr.msg_len <= sizeof(pkt.hdr)) {
				LOG_ERR("Invalid queued TX frame length %u", pkt.ipc_hdr.msg_len);
				free(pkt.buf);
				pkt.buf = NULL;
				continue;
			}

			payload_len = pkt.ipc_hdr.msg_len - sizeof(pkt.hdr);
			LOG_DBG("OUT dev %s msg len %x", ipmdev->name,
				pkt.ipc_hdr.msg_len);
			ret = ast_ipm_shmem_write(ipmdev, IPM_MCTP_CHANNEL, 0,
						  &pkt.hdr, sizeof(pkt.hdr));
			if (ret < 0) {
				LOG_ERR("ast_ipm_shmem_write header failed, ret=%d", ret);
				free(pkt.buf);
				pkt.buf = NULL;
				continue;
			}
			ret = ast_ipm_shmem_write(ipmdev, IPM_MCTP_CHANNEL, sizeof(pkt.hdr),
						  pkt.buf, payload_len);
			if (ret < 0) {
				LOG_ERR("ast_ipm_shmem_write payload failed, ret=%d", ret);
				free(pkt.buf);
				pkt.buf = NULL;
				continue;
			}
			send_len = sizeof(pkt.ipc_hdr);
			LOG_HEXDUMP_DBG(&pkt.ipc_hdr, sizeof(pkt.ipc_hdr),
					"IPC SEND HEADER");
			LOG_HEXDUMP_DBG(&pkt.hdr, sizeof(pkt.hdr), "MCTP SEND HEADER");
			ret = ipm_send(ipmdev, 1, 0, &pkt, send_len);
			if (ret != 0)
				LOG_ERR("MCTP IPC response send failed, ret=%d", ret);

			/* ipm_send() is synchronous when wait is nonzero. */
			free(pkt.buf);
			pkt.buf = NULL;
		}
	}
}

K_THREAD_DEFINE(ipm_mctp_tid, 1024, ipm_mctp_main, NULL, NULL, NULL, 5, 0, 0);

int ipm_init(void)
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
