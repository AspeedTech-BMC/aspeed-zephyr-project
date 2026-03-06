/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <stdlib.h>
#include <mctp.h>
#include <libutil.h>

#include <mctp_ipc.h>

LOG_MODULE_REGISTER(mctp_ipc, LOG_LEVEL_INF);


K_MSGQ_DEFINE(mctp_ipc_msgq_rx, sizeof(mctp_ipc_packet), 1, 4);
K_MSGQ_DEFINE(mctp_ipc_msgq_tx, sizeof(mctp_ipc_packet), 1, 4);

static uint16_t mctp_ipc_read(void *mctp_p, uint8_t *buf, uint32_t len,
				mctp_ext_params *extra_data)
{
	mctp_ipc_packet pkt;

	k_msgq_get(&mctp_ipc_msgq_rx, &pkt, K_FOREVER);
	LOG_HEXDUMP_DBG((void *)&pkt, 32 /* sizeof(pkt) */, "mctp_ipc_read");

	memcpy(buf, &pkt.hdr, 4);
	memcpy(buf+4, pkt.buf, pkt.ipc_hdr.msg_len - 4);

	return pkt.ipc_hdr.msg_len;
}


static uint16_t mctp_ipc_write(void *mctp_p, uint8_t *buf, uint32_t len,
				 mctp_ext_params extra_data)
{
	mctp_ipc_packet pkt;

	pkt.ipc_hdr.msg_len = len;
	memcpy(&pkt.hdr, buf, 4);
	pkt.buf = malloc(len - 4);
	memcpy(pkt.buf, buf + 4, len - 4);
	LOG_HEXDUMP_DBG(buf, len, "mctp_ipc_write");

	int ret = k_msgq_put(&mctp_ipc_msgq_tx, &pkt, K_NO_WAIT);
	if (ret != 0) {
		LOG_ERR("mctp_ipc_write failed, ret=%d", ret);
		return MCTP_ERROR;
	}

	return MCTP_SUCCESS;
}

uint8_t mctp_ipc_init(mctp *mctp_inst, mctp_medium_conf medium_conf)
{
	CHECK_NULL_ARG_WITH_RETURN(mctp_inst, MCTP_ERROR);

	mctp_inst->max_msg_size = 4096;
	mctp_inst->medium_conf = medium_conf;
	mctp_inst->read_data = mctp_ipc_read;
	mctp_inst->write_data = mctp_ipc_write;

	return MCTP_SUCCESS;
}

uint8_t mctp_ipc_deinit(mctp *mctp_inst)
{
	CHECK_NULL_ARG_WITH_RETURN(mctp_inst, MCTP_ERROR);

	return MCTP_SUCCESS;
}

int mctp_ipc_send_raw(mctp_ipc_packet *pkt)
{
	// Add Header Length
	k_msgq_put(&mctp_ipc_msgq_rx, pkt, K_NO_WAIT);
	
	return 0;
}
int mctp_ipc_send(mctp_ipc_packet *pkt)
{
	// Add Header Length
	pkt->ipc_hdr.msg_len += 4;

	pkt->hdr.hdr_ver = 0x01;
	pkt->hdr.dest_ep = 0x0a;
	pkt->hdr.src_ep = 0x0b;
	pkt->hdr.to = 0x01;
	pkt->hdr.pkt_seq = 0x01;
	pkt->hdr.som = 0x01;
	pkt->hdr.eom = 0x01;

	k_msgq_put(&mctp_ipc_msgq_rx, pkt, K_NO_WAIT);
	
	return 0;
}

int mctp_ipc_recv(mctp_ipc_packet *pkt2)
{
	return k_msgq_get(&mctp_ipc_msgq_tx, pkt2, K_SECONDS(1));
}

int mctp_ipc_send_recv(mctp_ipc_packet *pkt)
{
	// Add Header Length
	mctp_ipc_send(pkt);
	
	mctp_ipc_packet pkt2;

	int ret = mctp_ipc_send(&pkt2);

	LOG_INF("ipc_msgq_tx ret=%d", ret);
	LOG_HEXDUMP_DBG(&pkt2.hdr, pkt2.ipc_hdr.msg_len, "mctp_ipc responese");

	return 0;
}

