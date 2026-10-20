/*
 * Copyright (c) 2024 Intel Corporation
 * Copyright 2025 NXP
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * MCTP over USB (DSP0283) libmctp binding, ported from Zephyr 4.x
 * subsys/pmci/mctp/mctp_usb.c to this Zephyr 3.7 tree.
 */

#include <zephyr/sys/__assert.h>
#include <zephyr/kernel.h>
#include <zephyr/usb/usbd.h>
#include <zephyr/usb/usb_ch9.h>
#include <zephyr/drivers/usb/udc.h>
#include <zephyr/net/buf.h>
#include <mctp/mctp_usb.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(mctp_usb, CONFIG_MCTP_LOG_LEVEL);

#include <libmctp-alloc.h>

#define MCTP_USB_DMTF_0 0x1A
#define MCTP_USB_DMTF_1 0xB4

/* Workqueue budget: OUT buffers to parse per k_work run */
#define MCTP_USB_RX_WORK_BUDGET 4
#define MCTP_USB_ENABLED 0
/*
 * OUT is not armed: no buffer was free, or the enqueue failed. out_work
 * re-arms it once it frees a buffer, and out_retry after a delay, in case no
 * received buffer is waiting to be freed.
 */
#define MCTP_USB_OUT_STARVED 1
#define MCTP_USB_OUT_RETRY K_MSEC(10)
/*
 * Separate pools, so received data waiting for out_work can't take the
 * buffers a transmit needs. IN: a packet and its ZLP; tx_lock allows one
 * transmit at a time. OUT: one armed, the rest queued for parsing.
 */
#define MCTP_USB_IN_BUFS_PER_INSTANCE 2
#define MCTP_USB_OUT_BUFS_PER_INSTANCE 6
#define MCTP_USB_NUM_INSTANCES CONFIG_MCTP_USB_CLASS_INSTANCES_COUNT

/* Not defined by this Zephyr's usb_ch9.h */
#ifndef USB_BCC_MCTP
#define USB_BCC_MCTP 0x14
#endif

/* High-speed bulk max packet size, the largest an endpoint buffer must hold */
#define MCTP_USB_MAX_BULK_MPS 512

NET_BUF_POOL_FIXED_DEFINE(mctp_usb_in_pool,
			  MCTP_USB_NUM_INSTANCES * MCTP_USB_IN_BUFS_PER_INSTANCE,
			  MCTP_USB_MAX_BULK_MPS,
			  sizeof(struct udc_buf_info), NULL);

NET_BUF_POOL_FIXED_DEFINE(mctp_usb_out_pool,
			  MCTP_USB_NUM_INSTANCES * MCTP_USB_OUT_BUFS_PER_INSTANCE,
			  MCTP_USB_MAX_BULK_MPS,
			  sizeof(struct udc_buf_info), NULL);

struct mctp_usb_class_desc {
	struct usb_if_descriptor if0;
	struct usb_ep_descriptor if0_fs_out_ep;
	struct usb_ep_descriptor if0_fs_in_ep;
	struct usb_ep_descriptor if0_hs_out_ep;
	struct usb_ep_descriptor if0_hs_in_ep;
	struct usb_desc_header nil_desc;
};

struct mctp_usb_class_ctx {
	struct usbd_class_data *class_data;
	struct mctp_usb_class_desc *const desc;
	const struct usb_desc_header **const fs_desc;
	const struct usb_desc_header **const hs_desc;
	struct mctp_usb_class_inst *inst;
	uint8_t inst_idx;
	struct k_fifo rx_fifo;
	struct k_work out_work;
	struct k_work_delayable out_retry;
	atomic_t state;
	atomic_t in_pending;
	/*
	 * The IN packet and ZLP of the transmit in flight. Only their
	 * completions count down in_pending: disable clears these, so a buffer
	 * queued before it can't release tx_lock under a later transmit.
	 */
	atomic_ptr_t in_bufs[MCTP_USB_IN_BUFS_PER_INSTANCE];
};

/* An IN buffer completed or failed: release tx_lock after the transmit's last one */
static void mctp_usb_class_in_done(struct mctp_usb_class_ctx *ctx, struct net_buf *buf)
{
	for (size_t i = 0; i < ARRAY_SIZE(ctx->in_bufs); i++) {
		if (atomic_ptr_cas(&ctx->in_bufs[i], buf, NULL)) {
			if (atomic_dec(&ctx->in_pending) == 1) {
				k_sem_give(&ctx->inst->mctp_binding->tx_lock);
			}
			return;
		}
	}

	/* Queued before a disable, which already released tx_lock */
}

static uint8_t mctp_usb_class_get_bulk_in(struct usbd_class_data *const c_data);

/*
 * Drop the transmit in flight: cancel what is queued on IN, forget its
 * buffers (their cancelled completions are then ignored) and release
 * tx_lock. The stack shuts the endpoints down before it disables the class,
 * and this UDC starts a buffer queued on a disabled endpoint all the same,
 * where it stays busy until the next dequeue: without this, a packet queued
 * in that window holds tx_lock across the reconnect.
 */
static void mctp_usb_class_in_flush(struct mctp_usb_class_ctx *ctx)
{
	struct mctp_binding_usb *usb = ctx->inst->mctp_binding;

	(void)usbd_ep_dequeue(usbd_class_get_ctx(ctx->class_data),
			      mctp_usb_class_get_bulk_in(ctx->class_data));

	for (size_t i = 0; i < ARRAY_SIZE(ctx->in_bufs); i++) {
		atomic_ptr_clear(&ctx->in_bufs[i]);
	}
	atomic_set(&ctx->in_pending, 0);

	/* tx_lock's limit is 1, so a second release (disable and tx both) is harmless */
	if (k_sem_count_get(&usb->tx_lock) == 0) {
		k_sem_give(&usb->tx_lock);
	}
}

static struct net_buf *mctp_usb_class_buf_alloc(const uint8_t ep)
{
	struct net_buf *buf = NULL;
	struct udc_buf_info *bi;

	buf = net_buf_alloc(USB_EP_DIR_IS_IN(ep) ? &mctp_usb_in_pool : &mctp_usb_out_pool,
			    K_NO_WAIT);
	if (!buf) {
		return NULL;
	}

	bi = udc_get_buf_info(buf);
	bi->ep = ep;

	return buf;
}

static uint8_t mctp_usb_class_get_bulk_in(struct usbd_class_data *const c_data)
{
	struct mctp_usb_class_ctx *ctx = usbd_class_get_private(c_data);

	if (usbd_bus_speed(usbd_class_get_ctx(ctx->class_data)) == USBD_SPEED_HS) {
		return ctx->desc->if0_hs_in_ep.bEndpointAddress;
	}

	return ctx->desc->if0_fs_in_ep.bEndpointAddress;
}

static uint8_t mctp_usb_class_get_bulk_out(struct usbd_class_data *const c_data)
{
	struct mctp_usb_class_ctx *ctx = usbd_class_get_private(c_data);

	if (usbd_bus_speed(usbd_class_get_ctx(ctx->class_data)) == USBD_SPEED_HS) {
		return ctx->desc->if0_hs_out_ep.bEndpointAddress;
	}

	return ctx->desc->if0_fs_out_ep.bEndpointAddress;
}

/*
 * Queue the next OUT transfer. With the pool empty (received data not parsed
 * yet), leave OUT unarmed, so the host is NAKed, until a buffer is freed. A
 * failed enqueue is retried the same way, so OUT never stays unarmed for good.
 */
static void mctp_usb_class_arm_out(struct usbd_class_data *const c_data)
{
	struct mctp_usb_class_ctx *ctx = usbd_class_get_private(c_data);
	struct net_buf *nb;
	int err;

	if (!atomic_test_bit(&ctx->state, MCTP_USB_ENABLED)) {
		return;
	}

	nb = mctp_usb_class_buf_alloc(mctp_usb_class_get_bulk_out(c_data));
	if (nb == NULL) {
		goto starved;
	}

	err = usbd_ep_enqueue(c_data, nb);
	if (err == 0) {
		return;
	}

	LOG_ERR("Failed to enqueue OUT buffer: %d", err);
	net_buf_unref(nb);

starved:
	if (!atomic_test_and_set_bit(&ctx->state, MCTP_USB_OUT_STARVED)) {
		/* Outside usb->lock (USB stack thread, out_retry), so atomic */
		atomic_inc(&ctx->inst->mctp_binding->stats.rx_out_starved);
	}
	(void)k_work_schedule(&ctx->out_retry, MCTP_USB_OUT_RETRY);
}

static void mctp_usb_class_out_retry(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct mctp_usb_class_ctx *ctx = CONTAINER_OF(dwork, struct mctp_usb_class_ctx, out_retry);

	/* Unless out_work has re-armed OUT meanwhile */
	if (atomic_test_and_clear_bit(&ctx->state, MCTP_USB_OUT_STARVED)) {
		mctp_usb_class_arm_out(ctx->class_data);
	}
}

static void mctp_usb_reset_rx_state(struct mctp_binding_usb *usb)
{
	if (usb->rx_pkt != NULL) {
		mctp_pktbuf_free(usb->rx_pkt);
		usb->rx_pkt = NULL;
	}

	usb->rx_data_idx = 0;
	usb->rx_state = STATE_WAIT_HDR_DMTF0;
}

static int mctp_usb_tx_pkt(struct mctp_binding *binding, struct mctp_pktbuf *pkt)
{
	struct mctp_binding_usb *usb = CONTAINER_OF(binding, struct mctp_binding_usb, binding);
	struct usbd_class_data *c_data = usb->usb_class_data;
	struct mctp_usb_class_ctx *ctx;
	size_t len = mctp_pktbuf_size(pkt);
	size_t tx_len = len + MCTP_USB_HEADER_SIZE;
	struct net_buf *buf = NULL;
	struct net_buf *zlp = NULL;
	int err;
	uint16_t mps;
	bool need_zlp;

	if (c_data == NULL) {
		LOG_ERR("MCTP instance not found");
		return -ENODEV;
	}
	ctx = usbd_class_get_private(c_data);

	if (!atomic_test_bit(&ctx->state, MCTP_USB_ENABLED)) {
		return -EPERM;
	}

	if (tx_len > MCTP_USB_MAX_PACKET_LENGTH) {
		return -E2BIG;
	}

	err = k_sem_take(&usb->tx_lock, K_MSEC(CONFIG_MCTP_USB_TX_TIMEOUT));
	if (err != 0) {
		LOG_ERR("Semaphore could not be obtained");
		return err;
	}

	/*
	 * Again under tx_lock: a disable releases it while the transmit
	 * holding it may still be running, and a transmit that checked
	 * ENABLED before the disable must not then run alongside that one
	 * (they share tx_buf, in_bufs and in_pending). The disable clears
	 * ENABLED before it releases tx_lock, so this sees it.
	 */
	if (!atomic_test_bit(&ctx->state, MCTP_USB_ENABLED)) {
		k_sem_give(&usb->tx_lock);
		return -EPERM;
	}

	/* Determine MaxPacketSize for this speed */
	if (usbd_bus_speed(usbd_class_get_ctx(ctx->class_data)) == USBD_SPEED_HS) {
		mps = sys_le16_to_cpu(ctx->desc->if0_hs_in_ep.wMaxPacketSize);
	} else {
		mps = sys_le16_to_cpu(ctx->desc->if0_fs_in_ep.wMaxPacketSize);
	}

	need_zlp = (mps != 0U) && ((tx_len % mps) == 0U);

	/* If we need ZLP, allocate it FIRST to avoid half-inflight states */
	if (need_zlp) {
		zlp = mctp_usb_class_buf_alloc(mctp_usb_class_get_bulk_in(c_data));
		if (!zlp) {
			k_sem_give(&usb->tx_lock);
			LOG_ERR("Failed to allocate ZLP buffer");
			return -ENOMEM;
		}
	}

	/* Completion may happen very fast: set pending BEFORE enqueue */
	atomic_set(&ctx->in_pending, need_zlp ? 2 : 1);
	atomic_ptr_set(&ctx->in_bufs[1], zlp);

	usb->tx_buf[0] = MCTP_USB_DMTF_0;
	usb->tx_buf[1] = MCTP_USB_DMTF_1;
	usb->tx_buf[2] = 0;
	usb->tx_buf[3] = tx_len;

	/* Whole packet from its start; mctp_pktbuf_data() would skip the MCTP header */
	memcpy(&usb->tx_buf[MCTP_USB_HEADER_SIZE], mctp_pktbuf_hdr(pkt), len);

	LOG_HEXDUMP_DBG(usb->tx_buf, len + MCTP_USB_HEADER_SIZE, "buf = ");

	buf = mctp_usb_class_buf_alloc(mctp_usb_class_get_bulk_in(c_data));
	if (buf == NULL) {
		atomic_ptr_clear(&ctx->in_bufs[1]);
		atomic_set(&ctx->in_pending, 0);
		if (zlp) {
			net_buf_unref(zlp);
		}
		k_sem_give(&usb->tx_lock);
		LOG_ERR("Failed to allocate IN buffer");
		return -ENOMEM;
	}

	net_buf_add_mem(buf, usb->tx_buf, len + MCTP_USB_HEADER_SIZE);
	atomic_ptr_set(&ctx->in_bufs[0], buf);

	err = usbd_ep_enqueue(c_data, buf);
	if (err != 0) {
		atomic_ptr_clear(&ctx->in_bufs[0]);
		atomic_ptr_clear(&ctx->in_bufs[1]);
		atomic_set(&ctx->in_pending, 0);
		if (zlp) {
			net_buf_unref(zlp);
		}
		k_sem_give(&usb->tx_lock);
		LOG_ERR("Failed to enqueue IN buffer");
		net_buf_unref(buf);
		return err;
	}

	if (need_zlp) {
		LOG_DBG("TX len %zu is multiple of MPS %u, sending ZLP", tx_len, mps);
		err = usbd_ep_enqueue(c_data, zlp);
		if (err != 0) {
			/*
			 * The packet is already in flight, so this still counts
			 * as sent. Account for the ZLP as if it had completed:
			 * whichever of this and the packet's completion comes
			 * last releases tx_lock. Without the ZLP the host may
			 * run this transfer into the next one.
			 */
			LOG_ERR("Failed to enqueue ZLP: %d", err);
			mctp_usb_class_in_done(ctx, zlp);
			net_buf_unref(zlp);
		}
	}

	/* Disabled while queueing: the packet went to a shut-down endpoint */
	if (!atomic_test_bit(&ctx->state, MCTP_USB_ENABLED)) {
		mctp_usb_class_in_flush(ctx);
		return -EPERM;
	}

	return 0;
}

int mctp_usb_tx(struct mctp_binding *binding, struct mctp_pktbuf *pkt)
{
	struct mctp_binding_usb *usb = CONTAINER_OF(binding, struct mctp_binding_usb, binding);
	bool som = mctp_pktbuf_hdr(pkt)->flags_seq_tag & MCTP_HDR_FLAG_SOM;
	int err;

	/*
	 * Report a failed packet as sent, and so dropped. On any other error
	 * libmctp keeps the rest of a multi-packet message queued, and every
	 * later message on the bus fails as busy; on -EBUSY it waits for a
	 * mctp_binding_set_tx_enabled() this binding never makes. The rest of
	 * the message is dropped unsent, rather than each packet waiting out
	 * CONFIG_MCTP_USB_TX_TIMEOUT, and the receiver discards what it got.
	 */
	if (usb->tx_drop && !som) {
		usb->stats.tx_errors++;
		return 0;
	}

	err = mctp_usb_tx_pkt(binding, pkt);
	usb->tx_drop = err != 0;
	if (err == 0) {
		usb->stats.tx_pkts++;
	} else {
		usb->stats.tx_errors++;
	}

	return 0;
}

int mctp_usb_start(struct mctp_binding *binding)
{
	/* tx_lock and lock are initialized by MCTP_USB_DEFINE() */
	mctp_binding_set_tx_enabled(binding, true);

	return 0;
}

static void mctp_usb_class_out_work(struct k_work *work)
{
	struct mctp_usb_class_ctx *ctx = CONTAINER_OF(work, struct mctp_usb_class_ctx, out_work);
	struct mctp_binding_usb *usb = ctx->inst->mctp_binding;
	uint32_t budget = MCTP_USB_RX_WORK_BUDGET;
	uint16_t mps;

	if (!atomic_test_bit(&ctx->state, MCTP_USB_ENABLED)) {
		return;
	}

	if (usbd_bus_speed(usbd_class_get_ctx(ctx->class_data)) == USBD_SPEED_HS) {
		mps = sys_le16_to_cpu(ctx->desc->if0_hs_out_ep.wMaxPacketSize);
	} else {
		mps = sys_le16_to_cpu(ctx->desc->if0_fs_out_ep.wMaxPacketSize);
	}
	mps = MAX(mps, 1U);

	k_mutex_lock(&usb->lock, K_FOREVER);
	while (budget-- != 0U) {
		struct net_buf *rx = k_fifo_get(&ctx->rx_fifo, K_NO_WAIT);
		size_t i;

		if (rx == NULL) {
			break;
		}

		/* Parse directly from net_buf */
		for (i = 0U; i < rx->len; i++) {
			uint8_t byte = rx->data[i];

			switch (usb->rx_state) {
			case STATE_WAIT_HDR_DMTF0:
				if (byte == MCTP_USB_DMTF_0) {
					usb->rx_state = STATE_WAIT_HDR_DMTF1;
				}
				break;

			case STATE_WAIT_HDR_DMTF1:
				if (byte == MCTP_USB_DMTF_1) {
					usb->rx_state = STATE_WAIT_HDR_RSVD0;
				} else if (byte == MCTP_USB_DMTF_0) {
					/* treat as potential new start */
					usb->rx_state = STATE_WAIT_HDR_DMTF1;
				} else {
					usb->rx_state = STATE_WAIT_HDR_DMTF0;
				}
				break;

			case STATE_WAIT_HDR_RSVD0:
				/* As per the spec reserved byte(s) need to be ignored */
				if (byte != 0U) {
					LOG_DBG("Non-zero RSVD0 %02X ignored", byte);
				}
				usb->rx_state = STATE_WAIT_HDR_LEN;
				break;

			case STATE_WAIT_HDR_LEN:
				/*
				 * LEN is total framed length (hdr + payload)
				 * Payload length = LEN - MCTP_USB_HEADER_SIZE. The packet
				 * must hold at least an MCTP header: STATE_DATA only
				 * completes a packet after storing a byte, so an empty
				 * one would run past its buffer.
				 */
				if (byte < MCTP_USB_HEADER_SIZE + sizeof(struct mctp_hdr)) {
					LOG_ERR("Invalid LEN %02X", byte);
					usb->stats.rx_drops++;
					mctp_usb_reset_rx_state(usb);
					break;
				}

				usb->rx_data_idx = 0U;
				usb->rx_pkt = mctp_pktbuf_alloc(&usb->binding,
								byte - MCTP_USB_HEADER_SIZE);
				if (usb->rx_pkt == NULL) {
					LOG_ERR("Failed to alloc pktbuf");
					usb->stats.rx_drops++;
					mctp_usb_reset_rx_state(usb);
					break;
				}

				usb->rx_state = STATE_DATA;
				break;

			case STATE_DATA:
				/*
				 * If rx_pkt becomes NULL due to a reset, don't write.
				 * This also guards against any future logic changes.
				 */
				if (usb->rx_pkt == NULL) {
					mctp_usb_reset_rx_state(usb);
					break;
				}

				((uint8_t *)mctp_pktbuf_hdr(usb->rx_pkt))[usb->rx_data_idx++] = byte;

				if (usb->rx_data_idx == mctp_pktbuf_size(usb->rx_pkt)) {
					usb->stats.rx_pkts++;
					mctp_bus_rx(&usb->binding, usb->rx_pkt);
					mctp_pktbuf_free(usb->rx_pkt);
					usb->rx_pkt = NULL;
					mctp_usb_reset_rx_state(usb);
				}
				break;
			}
		}

		/*
		 * One transfer may hold several packets, and span several OUT
		 * buffers, so the parser carries its state from one buffer to
		 * the next. But a packet never continues past the end of its
		 * transfer (DSP0283), which a short USB packet or a ZLP marks:
		 * one still open there was cut short, so drop it rather than
		 * fill it with the next transfer's bytes. A lone 0x1A at the
		 * end (STATE_WAIT_HDR_DMTF1) was never a packet: just resync.
		 */
		if (rx->len == 0U || (rx->len % mps) != 0U) {
			if (usb->rx_state != STATE_WAIT_HDR_DMTF0 &&
			    usb->rx_state != STATE_WAIT_HDR_DMTF1) {
				LOG_WRN("Dropping a packet cut short by the end of its transfer");
				usb->stats.rx_drops++;
			}
			mctp_usb_reset_rx_state(usb);
		}

		net_buf_unref(rx);

		if (atomic_test_and_clear_bit(&ctx->state, MCTP_USB_OUT_STARVED)) {
			mctp_usb_class_arm_out(ctx->class_data);
		}
	}
	k_mutex_unlock(&usb->lock);

	/* If there is still work, reschedule */
	if (!k_fifo_is_empty(&ctx->rx_fifo)) {
		(void)k_work_submit(&ctx->out_work);
	}
}

static int mctp_usb_class_request(struct usbd_class_data *const c_data,
				  struct net_buf *buf, int err)
{
	struct mctp_usb_class_ctx *ctx = usbd_class_get_private(c_data);
	struct udc_buf_info *bi = udc_get_buf_info(buf);
	const uint8_t ep_in = mctp_usb_class_get_bulk_in(c_data);
	const uint8_t ep_out = mctp_usb_class_get_bulk_out(c_data);

	LOG_DBG("request for EP 0x%x", bi->ep);

	if (err != 0) {
		/* OUT error: free and try to re-arm if still enabled */
		if (bi->ep == ep_out) {
			net_buf_unref(buf);
			mctp_usb_class_arm_out(c_data);
			return 0;
		}

		/* IN error path: consume + account pending */
		if (bi->ep == ep_in) {
			mctp_usb_class_in_done(ctx, buf);
			net_buf_unref(buf);
			return 0;
		}

		net_buf_unref(buf);
		return 0;
	}

	if (bi->ep == ep_out) {
		/* Re-arm OUT first to avoid host-side stalls */
		mctp_usb_class_arm_out(c_data);

		/* Queue buffer for parsing and kick worker; a ZLP too, as it ends a transfer */
		k_fifo_put(&ctx->rx_fifo, buf);
		(void)k_work_submit(&ctx->out_work);
		return 0;
	}

	if (bi->ep == ep_in) {
		mctp_usb_class_in_done(ctx, buf);
		net_buf_unref(buf);
		return 0;
	}

	net_buf_unref(buf);
	return 0;
}

static void *mctp_usb_class_get_desc(struct usbd_class_data *const c_data,
				     const enum usbd_speed speed)
{
	struct mctp_usb_class_ctx *ctx = usbd_class_get_private(c_data);

	if (speed == USBD_SPEED_HS) {
		return ctx->hs_desc;
	}

	return ctx->fs_desc;
}

static void mctp_usb_class_enable(struct usbd_class_data *const c_data)
{
	struct mctp_usb_class_ctx *ctx = usbd_class_get_private(c_data);

	if (!atomic_test_and_set_bit(&ctx->state, MCTP_USB_ENABLED)) {
		/* Arm the first OUT transfer so the host's first write can complete */
		mctp_usb_class_arm_out(c_data);
		LOG_INF("MCTP USB enabled");
	}

	LOG_DBG("Enabled %s", c_data->name);
}

static void mctp_usb_class_disable(struct usbd_class_data *const c_data)
{
	struct mctp_usb_class_ctx *ctx = usbd_class_get_private(c_data);
	struct mctp_binding_usb *usb = ctx->inst->mctp_binding;
	struct k_work_sync sync;

	atomic_clear_bit(&ctx->state, MCTP_USB_ENABLED);
	/* With ENABLED clear, a retry already running can't arm OUT again */
	(void)k_work_cancel_delayable_sync(&ctx->out_retry, &sync);
	atomic_clear_bit(&ctx->state, MCTP_USB_OUT_STARVED);

	/*
	 * Unblock TX if host disconnects mid-IN, and cancel anything queued on
	 * IN since the endpoints were shut down. Before waiting for the worker:
	 * a reply it sends may be waiting for an IN completion, which this
	 * thread would deliver; with ENABLED clear, its next packet fails fast.
	 */
	mctp_usb_class_in_flush(ctx);

	/* Wait for a running worker, which may be parsing into rx_pkt */
	(void)k_work_cancel_sync(&ctx->out_work, &sync);

	/* The parser state is the worker's; reset it under the same lock */
	k_mutex_lock(&usb->lock, K_FOREVER);

	/* Drain and free any queued OUT buffers */
	while (1) {
		struct net_buf *rx = k_fifo_get(&ctx->rx_fifo, K_NO_WAIT);

		if (!rx) {
			break;
		}
		net_buf_unref(rx);
	}

	/* Reset RX parser state */
	mctp_usb_reset_rx_state(usb);

	k_mutex_unlock(&usb->lock);

	LOG_DBG("Disabled %s", c_data->name);
}

static int mctp_usb_class_init(struct usbd_class_data *const c_data)
{
	struct mctp_usb_class_ctx *ctx = usbd_class_get_private(c_data);
	size_t num_instances = 0;

	STRUCT_SECTION_COUNT(mctp_usb_class_inst, &num_instances);

	if (num_instances != MCTP_USB_NUM_INSTANCES) {
		LOG_ERR("The number of application instances (%zu) does not match the number "
			"specified by CONFIG_MCTP_USB_CLASS_INSTANCES_COUNT (%d)",
			num_instances, MCTP_USB_NUM_INSTANCES);
		return -EINVAL;
	}

	STRUCT_SECTION_GET(mctp_usb_class_inst, ctx->inst_idx, &ctx->inst);

	ctx->class_data = c_data;
	ctx->state = 0;

	/* Share USB class data with the MCTP USB binding */
	ctx->inst->mctp_binding->usb_class_data = c_data;

	k_fifo_init(&ctx->rx_fifo);
	k_work_init(&ctx->out_work, mctp_usb_class_out_work);
	k_work_init_delayable(&ctx->out_retry, mctp_usb_class_out_retry);
	atomic_set(&ctx->in_pending, 0);

	if (ctx->inst->subclass == USBD_MCTP_SUBCLASS_MANAGEMENT_CONTROLLER ||
	    ctx->inst->subclass == USBD_MCTP_SUBCLASS_MANAGED_DEVICE_ENDPOINT ||
	    ctx->inst->subclass == USBD_MCTP_SUBCLASS_HOST_INTERFACE_ENDPOINT) {
		ctx->desc->if0.bInterfaceSubClass = ctx->inst->subclass;
	} else {
		LOG_ERR("Invalid USB MCTP subclass");
		return -EINVAL;
	}

	if (ctx->inst->mctp_protocol == USBD_MCTP_PROTOCOL_1_X ||
	    ctx->inst->mctp_protocol == USBD_MCTP_PROTOCOL_2_X) {
		ctx->desc->if0.bInterfaceProtocol = ctx->inst->mctp_protocol;
	} else {
		LOG_ERR("Invalid MCTP protocol");
		return -EINVAL;
	}

	LOG_DBG("MCTP device %s initialized", ctx->inst->mctp_binding->binding.name);

	return 0;
}

struct usbd_class_api mctp_usb_class_api = {
	.request = mctp_usb_class_request,
	.enable = mctp_usb_class_enable,
	.disable = mctp_usb_class_disable,
	.init = mctp_usb_class_init,
	.get_desc = mctp_usb_class_get_desc,
};

#define DEFINE_MCTP_USB_CLASS_DESCRIPTORS(n, _)						\
	static struct mctp_usb_class_desc mctp_usb_class_desc_##n = {			\
		.if0 = {								\
			.bLength = sizeof(struct usb_if_descriptor),			\
			.bDescriptorType = USB_DESC_INTERFACE,				\
			.bInterfaceNumber = 0,						\
			.bAlternateSetting = 0,						\
			.bNumEndpoints = 2,						\
			.bInterfaceClass = USB_BCC_MCTP,				\
			.bInterfaceSubClass = 0,					\
			.bInterfaceProtocol = 1,					\
			.iInterface = 0							\
		},									\
		.if0_fs_out_ep = {							\
			.bLength = sizeof(struct usb_ep_descriptor),			\
			.bDescriptorType = USB_DESC_ENDPOINT,				\
			.bEndpointAddress = 0x01,					\
			.bmAttributes = USB_EP_TYPE_BULK,				\
			.wMaxPacketSize = sys_cpu_to_le16(64),				\
			.bInterval = 1							\
		},									\
		.if0_fs_in_ep = {							\
			.bLength = sizeof(struct usb_ep_descriptor),			\
			.bDescriptorType = USB_DESC_ENDPOINT,				\
			.bEndpointAddress = 0x81,					\
			.bmAttributes = USB_EP_TYPE_BULK,				\
			.wMaxPacketSize = sys_cpu_to_le16(64),				\
			.bInterval = 1							\
		},									\
		.if0_hs_out_ep = {							\
			.bLength = sizeof(struct usb_ep_descriptor),			\
			.bDescriptorType = USB_DESC_ENDPOINT,				\
			.bEndpointAddress = 0x01,					\
			.bmAttributes = USB_EP_TYPE_BULK,				\
			.wMaxPacketSize = sys_cpu_to_le16(512),				\
			.bInterval = 1							\
		},									\
		.if0_hs_in_ep = {							\
			.bLength = sizeof(struct usb_ep_descriptor),			\
			.bDescriptorType = USB_DESC_ENDPOINT,				\
			.bEndpointAddress = 0x81,					\
			.bmAttributes = USB_EP_TYPE_BULK,				\
			.wMaxPacketSize = sys_cpu_to_le16(512),				\
			.bInterval = 1							\
		},									\
		.nil_desc = {								\
			.bLength = 0,							\
			.bDescriptorType = 0						\
		}									\
	};										\
	const static struct usb_desc_header *mctp_usb_class_fs_desc_##n[] = {		\
		(struct usb_desc_header *)&mctp_usb_class_desc_##n.if0,			\
		(struct usb_desc_header *)&mctp_usb_class_desc_##n.if0_fs_in_ep,	\
		(struct usb_desc_header *)&mctp_usb_class_desc_##n.if0_fs_out_ep,	\
		(struct usb_desc_header *)&mctp_usb_class_desc_##n.nil_desc		\
	};										\
											\
	const static struct usb_desc_header *mctp_usb_class_hs_desc_##n[] = {		\
		(struct usb_desc_header *)&mctp_usb_class_desc_##n.if0,			\
		(struct usb_desc_header *)&mctp_usb_class_desc_##n.if0_hs_in_ep,	\
		(struct usb_desc_header *)&mctp_usb_class_desc_##n.if0_hs_out_ep,	\
		(struct usb_desc_header *)&mctp_usb_class_desc_##n.nil_desc		\
	};

#define DEFINE_MCTP_USB_CLASS_DATA(n, _)						\
	static struct mctp_usb_class_ctx mctp_usb_class_ctx_##n = {			\
		.desc = &mctp_usb_class_desc_##n,					\
		.fs_desc = mctp_usb_class_fs_desc_##n,					\
		.hs_desc = mctp_usb_class_hs_desc_##n,					\
		.inst_idx = n,								\
		.rx_fifo = Z_FIFO_INITIALIZER(mctp_usb_class_ctx_##n.rx_fifo),		\
		.state = ATOMIC_INIT(0),						\
		.in_pending = ATOMIC_INIT(0),						\
	};										\
											\
	USBD_DEFINE_CLASS(mctp_##n, &mctp_usb_class_api, &mctp_usb_class_ctx_##n, NULL);

LISTIFY(MCTP_USB_NUM_INSTANCES, DEFINE_MCTP_USB_CLASS_DESCRIPTORS, ())
LISTIFY(MCTP_USB_NUM_INSTANCES, DEFINE_MCTP_USB_CLASS_DATA, ())
