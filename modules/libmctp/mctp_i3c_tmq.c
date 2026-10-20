/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <zephyr/drivers/i3c.h>
#include <zephyr/drivers/i3c/target/i3c_target_mqueue.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/crc.h>
#include <mctp/mctp_i3c_tmq.h>

LOG_MODULE_REGISTER(mctp_i3c_tmq, CONFIG_MCTP_LOG_LEVEL);

#define I3C_RNW_WRITE	0
#define I3C_RNW_READ	1

/*
 * Start of the whole packet (MCTP header included). Not mctp_pktbuf_data(),
 * which points past the MCTP header at the payload.
 */
static uint8_t *mctp_i3c_tmq_pkt_start(struct mctp_pktbuf *pkt)
{
	return (uint8_t *)mctp_pktbuf_hdr(pkt);
}

/* DSP0233 PEC: CRC-8 over the target's address + R/W bit, then the packet */
static uint8_t mctp_i3c_tmq_pec(uint8_t addr, uint8_t rnw, const uint8_t *buf, size_t len)
{
	uint8_t addr_rnw = (addr << 1) | rnw;

	return crc8_ccitt(crc8_ccitt(0, &addr_rnw, 1), buf, len);
}

int mctp_i3c_tmq_start(struct mctp_binding *binding)
{
	struct mctp_binding_i3c_tmq *b = CONTAINER_OF(binding, struct mctp_binding_i3c_tmq, binding);
	const struct i3c_target_driver_api *api;
	int ret;

	if (!device_is_ready(b->tmq)) {
		LOG_ERR("%s not ready", b->tmq->name);
		return -ENODEV;
	}

	/* Attach the message queue to its controller so it starts receiving */
	api = b->tmq->api;
	ret = api->driver_register(b->tmq);
	if (ret) {
		LOG_ERR("%s: register failed (%d)", b->tmq->name, ret);
		return ret;
	}

	mctp_binding_set_tx_enabled(binding, true);

	return 0;
}

int mctp_i3c_tmq_tx(struct mctp_binding *binding, struct mctp_pktbuf *pkt)
{
	struct mctp_binding_i3c_tmq *b = CONTAINER_OF(binding, struct mctp_binding_i3c_tmq, binding);
	bool som = mctp_pktbuf_hdr(pkt)->flags_seq_tag & MCTP_HDR_FLAG_SOM;
	int ret;

	/*
	 * A failed packet is reported as sent, and so dropped. On any other
	 * error libmctp keeps the rest of a multi-packet message queued, and
	 * every later message on the bus fails as busy; on -EBUSY it waits for
	 * a mctp_binding_set_tx_enabled() this binding never makes. The rest
	 * of the message is dropped unsent, rather than each packet waiting
	 * for the bus controller to time out, and the receiver discards what
	 * it got.
	 */
	if (b->tx_drop && !som) {
		b->stats.tx_errors++;
		return 0;
	}
	b->tx_drop = false;

	if (IS_ENABLED(CONFIG_MCTP_I3C_TMQ_PEC)) {
		uint8_t pec = mctp_i3c_tmq_pec(i3c_target_mqueue_get_address(b->tmq),
					       I3C_RNW_READ, mctp_i3c_tmq_pkt_start(pkt),
					       mctp_pktbuf_size(pkt));

		/* Room for this is reserved by binding.pkt_trailer */
		if (mctp_pktbuf_push(pkt, &pec, 1)) {
			b->stats.tx_errors++;
			b->tx_drop = true;
			return 0;
		}
	}

	/* Blocks until the bus controller has read the packet */
	ret = i3c_target_mqueue_write(b->tmq, mctp_i3c_tmq_pkt_start(pkt), mctp_pktbuf_size(pkt));
	if (ret) {
		b->stats.tx_errors++;
		LOG_ERR("%s: tx of %zu bytes failed (%d)", b->tmq->name, mctp_pktbuf_size(pkt), ret);
		b->tx_drop = true;
		return 0;
	}

	b->stats.tx_pkts++;

	return 0;
}

int mctp_i3c_tmq_poll(struct mctp_binding_i3c_tmq *b)
{
	struct mctp_pktbuf *pkt;
	int len;

	/* All of msg-size, so a packet over pkt_size is dropped whole, not truncated */
	len = i3c_target_mqueue_read(b->tmq, b->rx_buf, b->rx_buf_size);
	if (len <= 0) {
		return 0;
	}

	b->stats.rx_pkts++;

	if (IS_ENABLED(CONFIG_MCTP_I3C_TMQ_PEC)) {
		uint8_t pec;

		if (len < 2) {
			b->stats.rx_drops++;
			return -EINVAL;
		}

		len--;
		pec = mctp_i3c_tmq_pec(i3c_target_mqueue_get_address(b->tmq), I3C_RNW_WRITE,
				       b->rx_buf, len);
		if (pec != b->rx_buf[len]) {
			b->stats.rx_pec_errors++;
			LOG_WRN("%s: PEC mismatch (got 0x%02x, expected 0x%02x), dropped",
				b->tmq->name, b->rx_buf[len], pec);
			return -EIO;
		}
	}

	if ((size_t)len > b->binding.pkt_size) {
		b->stats.rx_drops++;
		LOG_WRN("%s: %d-byte packet over the %zu-byte limit, dropped", b->tmq->name, len,
			b->binding.pkt_size);
		return -EMSGSIZE;
	}

	pkt = mctp_pktbuf_alloc(&b->binding, len);
	if (!pkt) {
		b->stats.rx_drops++;
		LOG_WRN("%s: no pktbuf for %d-byte packet, dropped", b->tmq->name, len);
		return -ENOMEM;
	}

	memcpy(mctp_i3c_tmq_pkt_start(pkt), b->rx_buf, len);
	/* mctp_bus_rx() does not take ownership; the rx callbacks run inside it */
	mctp_bus_rx(&b->binding, pkt);
	mctp_pktbuf_free(pkt);

	return 1;
}
