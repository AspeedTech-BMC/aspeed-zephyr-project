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

#define MCTP_IPC_TX_ENQUEUE_TIMEOUT_MS 1000U

struct mctp_ipc_rx_frame {
	uint16_t len;
	uint16_t reserved;
	uint8_t data[MCTP_IPC_RX_FRAME_SIZE];
};

K_MEM_SLAB_DEFINE(mctp_ipc_rx_slab, sizeof(struct mctp_ipc_rx_frame),
		  MCTP_IPC_RX_FRAME_COUNT, 4);
K_MSGQ_DEFINE(mctp_ipc_msgq_rx, sizeof(struct mctp_ipc_rx_frame *),
	      MCTP_IPC_RX_FRAME_COUNT, 4);
K_MSGQ_DEFINE(mctp_ipc_msgq_tx, sizeof(mctp_ipc_packet),
	      MCTP_IPC_TX_FRAME_COUNT, 4);

static uint32_t mctp_ipc_read(void *mctp_p, uint8_t *buf, uint32_t len,
				mctp_ext_params *extra_data)
{
	struct mctp_ipc_rx_frame *frame;
	int ret;

	ARG_UNUSED(mctp_p);
	ARG_UNUSED(extra_data);

	if (!buf || !len)
		return 0;

	ret = k_msgq_get(&mctp_ipc_msgq_rx, &frame, K_FOREVER);
	if (ret || !frame)
		return 0;

	if (frame->len > len) {
		LOG_ERR("RX frame length %u exceeds destination size %u", frame->len, len);
		k_mem_slab_free(&mctp_ipc_rx_slab, frame);
		return 0;
	}

	LOG_HEXDUMP_DBG(frame->data, frame->len, "mctp_ipc_read");
	memcpy(buf, frame->data, frame->len);
	len = frame->len;
	k_mem_slab_free(&mctp_ipc_rx_slab, frame);

	return len;
}


static uint32_t mctp_ipc_write(void *mctp_p, uint8_t *buf, uint32_t len,
				 mctp_ext_params extra_data)
{
	mctp_ipc_packet pkt = { 0 };
	size_t payload_len;
	int ret;

	ARG_UNUSED(mctp_p);
	ARG_UNUSED(extra_data);

	if (!buf || len <= sizeof(pkt.hdr)) {
		LOG_ERR("Invalid TX frame buffer or length %u", len);
		return MCTP_ERROR;
	}

	pkt.ipc_hdr.msg_len = len;
	payload_len = len - sizeof(pkt.hdr);
	memcpy(&pkt.hdr, buf, sizeof(pkt.hdr));
	pkt.buf = malloc(payload_len);
	if (!pkt.buf) {
		LOG_ERR("Failed to allocate %u-byte TX payload", (uint32_t)payload_len);
		return MCTP_ERROR;
	}
	memcpy(pkt.buf, buf + sizeof(pkt.hdr), payload_len);
	LOG_HEXDUMP_DBG(buf, len, "mctp_ipc_write");

	ret = k_msgq_put(&mctp_ipc_msgq_tx, &pkt,
			 K_MSEC(MCTP_IPC_TX_ENQUEUE_TIMEOUT_MS));
	if (ret != 0) {
		LOG_ERR("TX queue unavailable after %u ms, ret=%d",
			MCTP_IPC_TX_ENQUEUE_TIMEOUT_MS, ret);
		free(pkt.buf);
		return MCTP_ERROR;
	}

	return MCTP_SUCCESS;
}

uint8_t mctp_ipc_init(mctp *mctp_inst, mctp_medium_conf medium_conf)
{
	CHECK_NULL_ARG_WITH_RETURN(mctp_inst, MCTP_ERROR);

	mctp_inst->max_msg_size = 32768;
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
	struct mctp_ipc_rx_frame *frame;
	uint32_t payload_len;
	int ret;

	if (!pkt || !pkt->buf)
		return MCTP_ERROR;

	if (pkt->ipc_hdr.msg_len <= sizeof(pkt->hdr) ||
	    pkt->ipc_hdr.msg_len > MCTP_IPC_RX_FRAME_SIZE) {
		LOG_ERR("Invalid RX frame length %u", pkt->ipc_hdr.msg_len);
		return MCTP_ERROR;
	}

	ret = k_mem_slab_alloc(&mctp_ipc_rx_slab, (void **)&frame, K_NO_WAIT);
	if (ret) {
		LOG_WRN("RX frame dropped: all %u ingress buffers are busy",
			MCTP_IPC_RX_FRAME_COUNT);
		return MCTP_ERROR;
	}

	frame->len = pkt->ipc_hdr.msg_len;
	payload_len = frame->len - sizeof(pkt->hdr);
	memcpy(frame->data, &pkt->hdr, sizeof(pkt->hdr));
	memcpy(frame->data + sizeof(pkt->hdr), pkt->buf, payload_len);

	ret = k_msgq_put(&mctp_ipc_msgq_rx, &frame, K_NO_WAIT);
	if (ret) {
		LOG_WRN("RX frame dropped: ingress queue is full");
		k_mem_slab_free(&mctp_ipc_rx_slab, frame);
		return MCTP_ERROR;
	}

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

	return mctp_ipc_send_raw(pkt);
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

