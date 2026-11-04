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
#include <string.h>

#include "lstp_common.h"
#include "lstp_backend.h"
#include "lstp_channel.h"
#include "lstp_router.h"
#include "lstp_task.h"
#include "lstp_usb.h"

LOG_MODULE_REGISTER(lstp_task, LOG_LEVEL_ERR);

#define LSTP_MSG_QUEUE_SIZE     16
#define LSTP_USB_RESP_TIMEOUT   K_MSEC(250)

struct lstp_task_msg {
	uint8_t buffer[LSTP_MSG_SIZE];
	size_t  len;
	uint32_t session; /* USB session the request arrived in */
	uint8_t resp_channel_id;
};

K_MSGQ_DEFINE(lstp_req_queue, sizeof(struct lstp_task_msg), LSTP_MSG_QUEUE_SIZE, 4);

/* Kicks only coalesce into one wakeup; they never take a request queue slot. */
K_SEM_DEFINE(lstp_kick_sem, 0, 1);

static void lstp_task_thread_main(void *, void *, void *);

K_THREAD_DEFINE(lstp_task_id, 8192,
		lstp_task_thread_main, NULL, NULL, NULL,
		K_PRIO_PREEMPT(5), 0, 0);

static void poll_channels(void)
{
	STRUCT_SECTION_FOREACH(lstp_channel, ch) {
		/* The router never initialized channels the topology leaves out. */
		if (ch->id != LSTP_CHANNEL_ID_NONE && ch->poll != NULL) {
			ch->poll();
		}
	}
}

static size_t process_req(struct lstp_hdr *hdr, uint8_t resp_channel_id, uint8_t *resp_buf)
{
	const struct lstp_channel *ch = lstp_router_channel(hdr->channel_id);
	uint8_t *payload = (uint8_t *)hdr + sizeof(struct lstp_hdr);
	size_t payload_len = hdr->len_lsb | (hdr->len_msb << BYTE1_SHIFT);
	struct lstp_hdr *resp_hdr = (struct lstp_hdr *)resp_buf;
	size_t resp_payload_len = 0;
	bool send_response = true;
	lstp_status_t status;

	LOG_DBG("Task dequeued msg for channel %d", hdr->channel_id);

	if (ch == NULL || ch->receive == NULL) {
		LOG_WRN("Unhandled channel in task: %d", hdr->channel_id);
		status = LSTP_STATUS_NOT_SUPPORTED;
	} else {
		status = ch->receive(hdr->channel_id, hdr, payload, payload_len,
				     resp_buf + sizeof(struct lstp_hdr), &resp_payload_len,
				     &send_response);
	}

	if (!send_response) {
		return 0;
	}

	resp_hdr->channel_id      = resp_channel_id;
	resp_hdr->cmd_status_code = (uint8_t)status | LSTP_RESPONSE_BIT;
	resp_hdr->len_lsb = resp_payload_len & LSB_MASK;
	resp_hdr->len_msb = (resp_payload_len >> BYTE1_SHIFT) & LSB_MASK;

	return sizeof(struct lstp_hdr) + resp_payload_len;
}

static void lstp_task_thread_main(void *p1, void *p2, void *p3)
{
	struct lstp_task_msg msg;
	uint8_t resp_buf[LSTP_MSG_SIZE];
	struct k_poll_event events[] = {
		K_POLL_EVENT_INITIALIZER(K_POLL_TYPE_MSGQ_DATA_AVAILABLE,
					 K_POLL_MODE_NOTIFY_ONLY, &lstp_req_queue),
		K_POLL_EVENT_INITIALIZER(K_POLL_TYPE_SEM_AVAILABLE,
					 K_POLL_MODE_NOTIFY_ONLY, &lstp_kick_sem),
	};

	LOG_INF("OBMF background task started");

	while (1) {
		(void)k_poll(events, ARRAY_SIZE(events), K_FOREVER);
		events[0].state = K_POLL_STATE_NOT_READY;
		events[1].state = K_POLL_STATE_NOT_READY;

		/* Consume the kick before polling so a kick raised meanwhile is not lost. */
		(void)k_sem_take(&lstp_kick_sem, K_NO_WAIT);

		int got = k_msgq_get(&lstp_req_queue, &msg, K_NO_WAIT);

		if (got == 0) {
			/* A slot is free again: let the host send the next request. */
			lstp_usb_rx_resume();
		}
		/* Requests from a host that has since reset are never executed. */
		if (got == 0 && msg.session == lstp_usb_session()) {
			size_t resp_len = process_req((struct lstp_hdr *)msg.buffer,
						      msg.resp_channel_id, resp_buf);

			if (resp_len > 0) {
				int ret = lstp_usb_send_response_in(msg.session, resp_buf,
								    resp_len,
								    LSTP_USB_RESP_TIMEOUT);
				if (ret < 0 && ret != -ESTALE) {
					LOG_ERR("Task failed to send USB resp: %d", ret);
				}
			}
		}

		poll_channels();
	}
}

void lstp_task_drop_requests(void)
{
	k_msgq_purge(&lstp_req_queue);
}

bool lstp_task_queue_full(void)
{
	return k_msgq_num_free_get(&lstp_req_queue) == 0U;
}

int lstp_task_submit_req(uint8_t *buffer, size_t len, uint8_t resp_channel_id)
{
	if (len < sizeof(struct lstp_hdr) || len > LSTP_MSG_SIZE) {
		return -EINVAL;
	}

	/* Static: the only caller is lstp_router_receive() in the USB controller ISR. */
	static struct lstp_task_msg msg;

	msg.len = len;
	msg.session = lstp_usb_session();
	msg.resp_channel_id = resp_channel_id;
	memcpy(msg.buffer, buffer, len);

	return k_msgq_put(&lstp_req_queue, &msg, K_NO_WAIT);
}

void lstp_task_kick(void)
{
	k_sem_give(&lstp_kick_sem);
}
