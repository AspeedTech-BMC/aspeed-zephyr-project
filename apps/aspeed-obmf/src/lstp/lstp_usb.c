/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portions derived from NVIDIA OpenSMA (https://github.com/NVIDIA/OpenSMA),
 * licensed under Apache-2.0. Ported and modified by ASPEED.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/usb/usb_ch9.h>
#include <string.h>

#include "lstp_common.h"
#include "lstp_usb.h"
#include "lstp_router.h"
#include "lstp_task.h"
#include "lstp_transaction.h"

LOG_MODULE_REGISTER(lstp_usb, LOG_LEVEL_ERR);

#define LSTP_USB_TRACE 0

#define LSTP_USB_CLASS_SUBCLASS 0x00
#define LSTP_USB_CLASS_PROTOCOL 0x00
#define LSTP_USB_RESP_QUEUE_SIZE 8
#define LSTP_USB_EVENT_QUEUE_SIZE 24
#define LSTP_USB_RX_QUEUE_SIZE    8
#define LSTP_USB_BCC_VENDOR 0xFF

/*
 * The bulk endpoints are fixed at the high-speed 512 B size, which is not legal
 * at full speed; the legacy stack has no other-speed descriptors to fall back on.
 */
BUILD_ASSERT(IS_ENABLED(CONFIG_USB_DC_HAS_HS_SUPPORT),
	     "LSTP needs a high-speed USB device controller");

struct usb_lstp_config {
	struct usb_if_descriptor if0;
	struct usb_ep_descriptor if0_in_ep;
	struct usb_ep_descriptor if0_out_ep;
} __packed;

USBD_CLASS_DESCR_DEFINE(primary, 0) struct usb_lstp_config lstp_cfg = {
	.if0 = {
		.bLength = sizeof(struct usb_if_descriptor),
		.bDescriptorType = USB_DESC_INTERFACE,
		.bInterfaceNumber = 0,
		.bAlternateSetting = 0,
		.bNumEndpoints = 2,
		.bInterfaceClass = LSTP_USB_BCC_VENDOR,
		.bInterfaceSubClass = 0x3f, // for nv lstp driver
		.bInterfaceProtocol = 0x01, // for nv lstp driver
		.iInterface = 0,
	},
	.if0_in_ep = {
		.bLength = sizeof(struct usb_ep_descriptor),
		.bDescriptorType = USB_DESC_ENDPOINT,
		.bEndpointAddress = LSTP_IN_EP_ADDR,
		.bmAttributes = USB_DC_EP_BULK,
		.wMaxPacketSize = LSTP_USB_MAX_EP_BUFFER_SIZE,
		.bInterval = 0x00,
	},
	.if0_out_ep = {
		.bLength = sizeof(struct usb_ep_descriptor),
		.bDescriptorType = USB_DESC_ENDPOINT,
		.bEndpointAddress = LSTP_OUT_EP_ADDR,
		.bmAttributes = USB_DC_EP_BULK,
		.wMaxPacketSize = LSTP_USB_MAX_EP_BUFFER_SIZE,
		.bInterval = 0x00,
	},
};

static struct {
	uint8_t rx_buf[1024]; /* Sufficient for LSTP_MSG_SIZE */
	size_t rx_len;
} usb_dev_data;

/*
 * TX packets are built in place in a slab block and queued by pointer, so no
 * sender needs a packet-sized buffer on its stack (the USB and system work
 * queues only have 1 KiB).
 */
struct lstp_usb_tx_msg {
	struct k_mem_slab *slab;
	atomic_val_t session; /* lstp_usb_tx_session when the packet was built */
	size_t len;
	uint8_t buf[LSTP_MSG_SIZE];
};

/* Use a dedicated preemptible TX workqueue to keep USB transfers responsive during UART floods. */
#define LSTP_USB_TXQ_STACK_SIZE 1024
#define LSTP_USB_TXQ_PRIORITY   K_PRIO_PREEMPT(4)

#define LSTP_USB_TX_RETRY_DELAY K_USEC(200)

static atomic_t lstp_usb_configured;
static atomic_t lstp_usb_in_busy;
static struct k_work_delayable lstp_usb_tx_work;
static struct k_work_q lstp_usb_txq;
static K_THREAD_STACK_DEFINE(lstp_usb_txq_stack, LSTP_USB_TXQ_STACK_SIZE);

/* Each queue is as deep as its slab, so a put after a successful alloc cannot fail. */
K_MEM_SLAB_DEFINE_STATIC(lstp_usb_resp_slab, sizeof(struct lstp_usb_tx_msg),
			 LSTP_USB_RESP_QUEUE_SIZE, 4);
K_MEM_SLAB_DEFINE_STATIC(lstp_usb_event_slab, sizeof(struct lstp_usb_tx_msg),
			 LSTP_USB_EVENT_QUEUE_SIZE, 4);
K_MSGQ_DEFINE(lstp_usb_resp_queue, sizeof(struct lstp_usb_tx_msg *),
	      LSTP_USB_RESP_QUEUE_SIZE, 4);
K_MSGQ_DEFINE(lstp_usb_event_queue, sizeof(struct lstp_usb_tx_msg *),
	      LSTP_USB_EVENT_QUEUE_SIZE, 4);

/* Owned by the TX work: the packet being sent, and the one on the wire. */
static struct lstp_usb_tx_msg *lstp_usb_tx_current;
static struct lstp_usb_tx_msg *lstp_usb_tx_inflight;
static atomic_t lstp_usb_response_drops;
static atomic_t lstp_usb_event_drops;
static atomic_t lstp_usb_rx_drops;
static atomic_t lstp_usb_write_errors;
static atomic_t lstp_usb_tx_high_water;

/* Reschedule also re-arms running work, avoiding lost completion kicks. */
static inline void lstp_usb_tx_kick_after(k_timeout_t delay)
{
	(void)k_work_reschedule_for_queue(&lstp_usb_txq, &lstp_usb_tx_work, delay);
}

static void lstp_usb_tx_free(struct lstp_usb_tx_msg **msg)
{
	if (*msg != NULL) {
		k_mem_slab_free((*msg)->slab, *msg);
		*msg = NULL;
	}
}

static void lstp_usb_tx_purge(struct k_msgq *queue)
{
	struct lstp_usb_tx_msg *msg;

	while (k_msgq_get(queue, &msg, K_NO_WAIT) == 0) {
		lstp_usb_tx_free(&msg);
	}
}

static void lstp_usb_update_high_water(void)
{
	atomic_val_t used = k_mem_slab_num_used_get(&lstp_usb_resp_slab) +
			    k_mem_slab_num_used_get(&lstp_usb_event_slab);
	atomic_val_t old = atomic_get(&lstp_usb_tx_high_water);

	while (used > old && !atomic_cas(&lstp_usb_tx_high_water, old, used)) {
		old = atomic_get(&lstp_usb_tx_high_water);
	}
}

/*
 * Bus reset/disconnect only flags the drop; the TX work does it, so it never
 * races a usb_write() or a copy into lstp_usb_tx_current.
 */
static atomic_t lstp_usb_tx_drop_requested;

/*
 * Bumped on every reset/disconnect. A sender preempted between its
 * configured check and k_msgq_put() can still queue a packet after the
 * purge; the session tag lets the TX kick drop it instead of sending it.
 */
static atomic_t lstp_usb_tx_session;

static atomic_t lstp_usb_rx_paused;

static void lstp_usb_tx_drop_pending(void)
{
	atomic_inc(&lstp_usb_tx_session);
	atomic_set(&lstp_usb_tx_drop_requested, 1);
	lstp_usb_tx_kick_after(K_NO_WAIT);
}

static void lstp_usb_tx_kick(struct k_work *work)
{
	uint32_t bytes_written;
	int ret;

	ARG_UNUSED(work);

	if (atomic_cas(&lstp_usb_tx_drop_requested, 1, 0)) {
		lstp_usb_tx_purge(&lstp_usb_resp_queue);
		lstp_usb_tx_purge(&lstp_usb_event_queue);
		lstp_usb_tx_free(&lstp_usb_tx_current);
		lstp_usb_tx_free(&lstp_usb_tx_inflight);
		atomic_clear(&lstp_usb_in_busy);
	}

	if (!atomic_get(&lstp_usb_configured) || atomic_get(&lstp_usb_in_busy)) {
		return;
	}

	/* in_busy is clear, so the previous transfer has completed. */
	lstp_usb_tx_free(&lstp_usb_tx_inflight);

	while (lstp_usb_tx_current == NULL) {
		if (k_msgq_get(&lstp_usb_resp_queue, &lstp_usb_tx_current, K_NO_WAIT) != 0 &&
		    k_msgq_get(&lstp_usb_event_queue, &lstp_usb_tx_current, K_NO_WAIT) != 0) {
			return;
		}
		if (lstp_usb_tx_current->session != atomic_get(&lstp_usb_tx_session)) {
			lstp_usb_tx_free(&lstp_usb_tx_current);
		}
	}

	if (!atomic_cas(&lstp_usb_in_busy, 0, 1)) {
		return;
	}

	/*
	 * USB_DC_RESET comes from the controller ISR, so a reset can still land
	 * between this check and arming the DMA. That packet cannot reach the
	 * next host: (re)configuration resets the endpoint, which cancels it, and
	 * USB_DC_CONFIGURED starts a fresh TX session. SET_CONFIGURATION itself
	 * runs in the (higher-priority) USB work queue thread, so the scheduler
	 * is locked across check + arm: the endpoint reset of a reconfiguration
	 * always comes after an arm, never between the check and the arm.
	 * Interrupts stay enabled; masking them delayed the UART RX ISR enough
	 * to overrun its FIFO.
	 * usb_dc_ep_write() never blocks, unlike usb_write(), which yields on
	 * -EAGAIN; -EAGAIN is retried below.
	 *
	 * No ZLP after a full 512 B message: every LSTP message fits one
	 * wMaxPacketSize packet and the host driver reads one packet per message.
	 */
	k_sched_lock();
	if (!atomic_get(&lstp_usb_configured) ||
	    lstp_usb_tx_current->session != atomic_get(&lstp_usb_tx_session)) {
		k_sched_unlock();
		atomic_clear(&lstp_usb_in_busy);
		lstp_usb_tx_free(&lstp_usb_tx_current);
		return;
	}
	ret = usb_dc_ep_write(LSTP_IN_EP_ADDR, lstp_usb_tx_current->buf,
			      lstp_usb_tx_current->len, &bytes_written);
	k_sched_unlock();
	if (ret < 0) {
		atomic_clear(&lstp_usb_in_busy);
		if (ret != -EAGAIN) {
			LOG_ERR("USB write failed: %d", ret);
			atomic_inc(&lstp_usb_write_errors);
			lstp_usb_tx_free(&lstp_usb_tx_current);
		}
		/* Back off while the IN endpoint is busy to avoid spinning. */
		lstp_usb_tx_kick_after(LSTP_USB_TX_RETRY_DELAY);
		return;
	}

	if (bytes_written != lstp_usb_tx_current->len) {
		/* The tail never reaches the host; count it as a failed write. */
		LOG_ERR("USB short write: %u of %zu", bytes_written, lstp_usb_tx_current->len);
		atomic_inc(&lstp_usb_write_errors);
	}

	lstp_usb_tx_inflight = lstp_usb_tx_current;
	lstp_usb_tx_current = NULL;
}

/*
 * Set while the OUT endpoint is left un-armed because the task queue is full:
 * the controller NAKs the host until the task frees a slot, so requests are
 * held back by USB flow control instead of being dropped.
 */
void lstp_usb_rx_resume(void)
{
	if (atomic_cas(&lstp_usb_rx_paused, 1, 0)) {
		usb_ep_read_continue(LSTP_OUT_EP_ADDR);
	}
}

static void lstp_usb_rx_rearm(uint8_t ep)
{
	if (lstp_task_queue_full()) {
		atomic_set(&lstp_usb_rx_paused, 1);
		/* The task may have freed a slot in between; never stay paused. */
		if (!lstp_task_queue_full()) {
			lstp_usb_rx_resume();
		}
		return;
	}
	usb_ep_read_continue(ep);
}

static void lstp_usb_bulk_out(uint8_t ep, enum usb_dc_ep_cb_status_code ep_status)
{
	uint32_t bytes_read = 0U;
	int ret;

	ret = usb_ep_read_wait(ep, usb_dev_data.rx_buf, sizeof(usb_dev_data.rx_buf), &bytes_read);
	if (ret < 0) {
		/* rx_buf still holds the previous request; never route it again. */
		usb_ep_read_continue(ep);
		atomic_inc(&lstp_usb_rx_drops);
		return;
	}

#if LSTP_USB_TRACE
	LOG_HEXDUMP_DBG(usb_dev_data.rx_buf, (bytes_read > 64 ? 64 : bytes_read), "USB RX Packets");
#endif

	if (bytes_read > 0U && lstp_router_receive(usb_dev_data.rx_buf, bytes_read) < 0) {
		atomic_inc(&lstp_usb_rx_drops);
	}
	lstp_usb_rx_rearm(ep);
}

static void lstp_usb_bulk_in(uint8_t ep, enum usb_dc_ep_cb_status_code ep_status)
{
	atomic_clear(&lstp_usb_in_busy);
	lstp_usb_tx_kick_after(K_NO_WAIT);
#if LSTP_USB_TRACE
	LOG_DBG("Bulk IN transaction complete on EP 0x%02x", ep);
#endif
}

static struct usb_ep_cfg_data lstp_ep_data[] = {
	{
		.ep_cb = lstp_usb_bulk_out,
		.ep_addr = LSTP_OUT_EP_ADDR
	},
	{
		.ep_cb = lstp_usb_bulk_in,
		.ep_addr = LSTP_IN_EP_ADDR
	}
};

static void lstp_interface_config(struct usb_desc_header *head, uint8_t bInterfaceNumber)
{
	ARG_UNUSED(head);
	lstp_cfg.if0.bInterfaceNumber = bInterfaceNumber;
}

/* The host went away (reset, unconfigure, disconnect, error): stop TX for it. */
static void lstp_usb_host_gone(void)
{
	atomic_clear(&lstp_usb_configured);
	lstp_usb_tx_drop_pending();
	lstp_transaction_transport_reset();
	lstp_router_host_reset();
}

/*
 * SET_CONFIGURATION and SET_INTERFACE reset both bulk endpoints, configuring
 * IN before OUT and sleeping in between, so TX may have armed an old-session
 * packet on the freshly reset IN DMA, or had one cancelled with no completion
 * (leaving write_busy and in_busy set). Reset the IN endpoint again here,
 * before the host can send IN tokens (the status stage follows this
 * callback), and start a fresh session as for any host change.
 */
static void lstp_usb_endpoints_reset(void)
{
	const struct usb_dc_ep_cfg_data in_cfg = {
		.ep_addr = LSTP_IN_EP_ADDR,
		.ep_mps = LSTP_USB_MAX_EP_BUFFER_SIZE,
		.ep_type = USB_DC_EP_BULK,
	};

	(void)usb_dc_ep_disable(LSTP_IN_EP_ADDR);
	(void)usb_dc_ep_configure(&in_cfg);
	(void)usb_dc_ep_enable(LSTP_IN_EP_ADDR);
	lstp_usb_tx_drop_pending();
	lstp_transaction_transport_reset();
	lstp_router_host_reset();
	atomic_set(&lstp_usb_configured, 1);
	lstp_usb_tx_kick_after(K_NO_WAIT);
}

static void lstp_usb_status_cb(struct usb_cfg_data *cfg,
		enum usb_dc_status_code status,
		const uint8_t *param)
{
	ARG_UNUSED(cfg);

	switch (status) {
	case USB_DC_ERROR:
		lstp_usb_host_gone();
		LOG_ERR("USB device error");
		break;
	case USB_DC_RESET:
		lstp_usb_host_gone();
		LOG_INF("USB device reset");
		break;
	case USB_DC_CONNECTED:
		LOG_INF("USB device connected");
		break;
	case USB_DC_CONFIGURED:
		/* SET_CONFIGURATION(0) is reported as CONFIGURED with *param == 0. */
		if (param == NULL || *param == 0U) {
			lstp_usb_host_gone();
			LOG_INF("USB device unconfigured");
			break;
		}
		lstp_usb_endpoints_reset();
		LOG_INF("USB device configured");
		break;
	case USB_DC_INTERFACE: {
		const struct usb_if_descriptor *iface = (const void *)param;

		/* Only alt 0 enables our endpoints; NULL means no matching alt. */
		if (iface == NULL || iface->bAlternateSetting != 0U) {
			lstp_usb_host_gone();
		} else if (atomic_get(&lstp_usb_configured)) {
			lstp_usb_endpoints_reset();
			LOG_INF("USB interface reset");
		}
		break;
	}
	case USB_DC_DISCONNECTED:
		lstp_usb_host_gone();
		LOG_INF("USB device disconnected");
		break;
	default:
		break;
	}
}

static int lstp_usb_class_handle_req(struct usb_setup_packet *pSetup, int32_t *len, uint8_t **data)
{
	return -ENOTSUP;
}

static int lstp_usb_vendor_handle_req(struct usb_setup_packet *pSetup, int32_t *len, uint8_t **data)
{
	return -ENOTSUP;
}

USBD_DEFINE_CFG_DATA(lstp_usb_config) = {
	.usb_device_description = NULL,
	.interface_config = lstp_interface_config,
	.interface_descriptor = &lstp_cfg.if0,
	.cb_usb_status = lstp_usb_status_cb,
	.interface = {
		.class_handler = lstp_usb_class_handle_req,
		.custom_handler = NULL,
		.vendor_handler = lstp_usb_vendor_handle_req,
	},
	.num_endpoints = ARRAY_SIZE(lstp_ep_data),
	.endpoint = lstp_ep_data
};

int lstp_usb_init(void)
{
	LOG_INF("Initializing OBMF USB transport");
	k_work_init_delayable(&lstp_usb_tx_work, lstp_usb_tx_kick);
	k_work_queue_start(&lstp_usb_txq, lstp_usb_txq_stack,
			   K_THREAD_STACK_SIZEOF(lstp_usb_txq_stack),
			   LSTP_USB_TXQ_PRIORITY, NULL);
	k_thread_name_set(&lstp_usb_txq.thread, "lstp_usb_tx");
	int ret = usb_enable(NULL);
	if (ret < 0) {
		LOG_ERR("Failed to enable USB: %d", ret);
		return ret;
	}
	return 0;
}

/* Queue head followed by tail as one packet. */
static int lstp_usb_enqueue(struct k_mem_slab *slab, struct k_msgq *queue,
			    const void *head, size_t head_len, const void *tail, size_t tail_len,
			    k_timeout_t timeout, atomic_t *drop_counter, atomic_val_t session)
{
	struct lstp_usb_tx_msg *msg;

	/* Built for a host that has since reset: it must never reach the new one. */
	if (session != atomic_get(&lstp_usb_tx_session)) {
		return -ESTALE;
	}

	if (head_len + tail_len > sizeof(msg->buf)) {
		return -EMSGSIZE;
	}

	if (!atomic_get(&lstp_usb_configured)) {
		return -ENODEV;
	}

	if (k_is_in_isr()) {
		timeout = K_NO_WAIT;
	}

	if (k_mem_slab_alloc(slab, (void **)&msg, timeout) != 0) {
		atomic_inc(drop_counter);
		return -ENOSPC;
	}

	msg->slab = slab;
	msg->session = session;
	msg->len = head_len + tail_len;
	memcpy(msg->buf, head, head_len);
	if (tail_len != 0U) {
		memcpy(msg->buf + head_len, tail, tail_len);
	}
	(void)k_msgq_put(queue, &msg, K_NO_WAIT);

	lstp_usb_update_high_water();
	lstp_usb_tx_kick_after(K_NO_WAIT);

	return 0;
}

uint32_t lstp_usb_session(void)
{
	return (uint32_t)atomic_get(&lstp_usb_tx_session);
}

int lstp_usb_send_response(const uint8_t *data, size_t len, k_timeout_t timeout)
{
	return lstp_usb_send_response_in(lstp_usb_session(), data, len, timeout);
}

int lstp_usb_send_response_in(uint32_t session, const uint8_t *data, size_t len,
			      k_timeout_t timeout)
{
	return lstp_usb_enqueue(&lstp_usb_resp_slab, &lstp_usb_resp_queue, data, len, NULL, 0U,
				timeout, &lstp_usb_response_drops, (atomic_val_t)session);
}

int lstp_usb_send_event(const uint8_t *data, size_t len)
{
	return lstp_usb_send_event_in(lstp_usb_session(), data, len);
}

int lstp_usb_send_event_in(uint32_t session, const uint8_t *data, size_t len)
{
	return lstp_usb_enqueue(&lstp_usb_event_slab, &lstp_usb_event_queue, data, len, NULL,
				0U, K_NO_WAIT, &lstp_usb_event_drops, (atomic_val_t)session);
}

int lstp_usb_send_event_parts(const struct lstp_hdr *hdr, const void *payload,
			      size_t payload_len)
{
	return lstp_usb_enqueue(&lstp_usb_event_slab, &lstp_usb_event_queue, hdr, sizeof(*hdr),
				payload, payload_len, K_NO_WAIT, &lstp_usb_event_drops,
				atomic_get(&lstp_usb_tx_session));
}

void lstp_usb_get_stats(struct lstp_usb_stats *stats)
{
	if (stats == NULL) {
		return;
	}

	stats->response_drops = atomic_get(&lstp_usb_response_drops);
	stats->event_drops = atomic_get(&lstp_usb_event_drops);
	stats->rx_drops = atomic_get(&lstp_usb_rx_drops);
	stats->write_errors = atomic_get(&lstp_usb_write_errors);
	stats->tx_high_water = atomic_get(&lstp_usb_tx_high_water);
}
