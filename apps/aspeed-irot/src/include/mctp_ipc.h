/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <zephyr/kernel.h>
#include <mctp.h>

/* IPM device and shared memory channel used for MCTP over IPC. */
#define MCTP_IPC_DEV_NAME "ipc0@200"
#define MCTP_IPC_CHANNEL 0

#define MCTP_IPC_RX_FRAME_SIZE 2048U
/* Upper bound for max_msg_size, which also sizes the RX and reassembly buffers. */
#define MCTP_IPC_MAX_MSG_SIZE 4096U
#define MCTP_IPC_RX_FRAME_COUNT 16U
#define MCTP_IPC_TX_FRAME_COUNT 16U

struct mctp_ipc_hdr {
	uint32_t msg_len;
};

typedef struct _mctp_ipc_packet {
	struct mctp_ipc_hdr ipc_hdr; // hdr + buf
	mctp_hdr hdr;
	// uint8_t buf[32 - 8];
#if 0
	uint8_t buf[1024 - 9];
#else
	uint8_t *buf;
#endif
} mctp_ipc_packet;

int mctp_ipc_send_recv(mctp_ipc_packet *pkt);
int mctp_ipc_send(mctp_ipc_packet *pkt);
int mctp_ipc_send_raw(mctp_ipc_packet *pkt);
int mctp_ipc_recv(mctp_ipc_packet *pkt);
uint8_t mctp_ipc_init(mctp *mctp_inst, mctp_medium_conf medium_conf);
uint8_t mctp_ipc_deinit(mctp *mctp_inst);
