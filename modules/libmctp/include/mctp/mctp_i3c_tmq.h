/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * libmctp binding for an I3C target (secondary) controller, carried over an
 * i3c-target-mqueue device.
 *
 * Received packets are queued by the mqueue driver and handed to libmctp by
 * mctp_i3c_tmq_poll(). With CONFIG_MCTP_I3C_TMQ_PEC each packet on the wire
 * carries a trailing DSP0233 PEC byte, checked on receive and appended on
 * transmit. Packets libmctp sends go out through
 * i3c_target_mqueue_write(), which raises the MCTP pending-read IBI and
 * blocks until the bus controller reads them (or the controller driver
 * times out).
 *
 * libmctp is not thread-safe: callers must serialize mctp_i3c_tmq_poll()
 * with every other call into the same struct mctp, e.g. mctp_message_tx().
 */

#ifndef MCTP_MCTP_I3C_TMQ_H_
#define MCTP_MCTP_I3C_TMQ_H_

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/sys/util.h>
#include <libmctp.h>

struct mctp_i3c_tmq_stats {
	uint32_t rx_pkts;
	uint32_t rx_drops;
	uint32_t rx_pec_errors;
	uint32_t tx_pkts;
	uint32_t tx_errors;
};

struct mctp_binding_i3c_tmq {
	/** @cond INTERNAL_HIDDEN */
	struct mctp_binding binding;
	const struct device *tmq;
	uint8_t *rx_buf;
	size_t rx_buf_size;
	/* A packet failed: drop the rest of its message unsent */
	bool tx_drop;
	/** @endcond */
	/** Packet counters, maintained by the binding */
	struct mctp_i3c_tmq_stats stats;
};

int mctp_i3c_tmq_start(struct mctp_binding *binding);
int mctp_i3c_tmq_tx(struct mctp_binding *binding, struct mctp_pktbuf *pkt);

/**
 * @brief Hand the next queued received packet, if any, to libmctp.
 *
 * @return 1 if a packet was processed, 0 if the queue was empty, or a
 *         negative errno if the packet could not be delivered.
 */
int mctp_i3c_tmq_poll(struct mctp_binding_i3c_tmq *b);

#define MCTP_I3C_TMQ_PEC_LEN COND_CODE_1(CONFIG_MCTP_I3C_TMQ_PEC, (1), (0))

/* Largest packet (MCTP header and payload) the binding sends and accepts */
#define MCTP_I3C_TMQ_PKT_SIZE(_node_id)                                                            \
	COND_CODE_1(CONFIG_MCTP_I3C_TMQ_LARGE_PACKETS,                                             \
		    ((DT_PROP(_node_id, msg_size) - MCTP_I3C_TMQ_PEC_LEN)),                        \
		    ((MCTP_PACKET_SIZE(MCTP_BTU))))

/**
 * @brief Define a binding on an i3c-target-mqueue devicetree node.
 *
 * The node's msg-size bounds a whole wire packet: MCTP header, payload and
 * the PEC byte, if used. It must hold at least a baseline (64-byte payload)
 * MCTP packet. Packets are baseline ones unless
 * CONFIG_MCTP_I3C_TMQ_LARGE_PACKETS lets them grow to msg-size.
 */
#define MCTP_I3C_TMQ_DT_DEFINE(_name, _node_id)                                                    \
	BUILD_ASSERT(DT_PROP(_node_id, msg_size) >=                                                \
			     MCTP_PACKET_SIZE(MCTP_BTU) + MCTP_I3C_TMQ_PEC_LEN,                    \
		     "i3c-target-mqueue msg-size too small for an MCTP baseline packet");          \
	static uint8_t _name##_rx_buf[DT_PROP(_node_id, msg_size)];                                \
	static uint8_t _name##_tx_storage[MCTP_PKTBUF_SIZE(DT_PROP(_node_id, msg_size))]          \
		PKTBUF_STORAGE_ALIGN;                                                              \
	struct mctp_binding_i3c_tmq _name = {                                                      \
		.binding = {                                                                       \
			.name = STRINGIFY(_name),                                                  \
			.version = 1,                                                              \
			.start = mctp_i3c_tmq_start,                                               \
			.tx = mctp_i3c_tmq_tx,                                                     \
			.pkt_size = MCTP_I3C_TMQ_PKT_SIZE(_node_id),                               \
			.pkt_trailer = MCTP_I3C_TMQ_PEC_LEN,                                       \
			.tx_storage = _name##_tx_storage,                                          \
		},                                                                                 \
		.tmq = DEVICE_DT_GET(_node_id),                                                    \
		.rx_buf = _name##_rx_buf,                                                          \
		.rx_buf_size = sizeof(_name##_rx_buf),                                             \
	}

#endif /* MCTP_MCTP_I3C_TMQ_H_ */
