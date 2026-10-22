/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * SPDM bridge to the SSMCU: SPDM requests that arrive over MCTP on any bus
 * (message type 0x05, or 0x06 for SPDM Secured Messages; MCTP type byte
 * included) are forwarded to the SSMCU's SPDM responder over the PSP IPC
 * channel (aspeed_psp_ipc.h), and its response goes back on the bus, to the
 * EID and with the tag the request came with.
 *
 * The rx callback only queues a request (it runs with the bus lock held);
 * one thread forwards them one at a time, as the channel carries a single
 * request in flight. Bodies sit in the IPC driver's window for the SPDM IPI
 * (the board's shmem_ch0): the request is written to its TX half before the
 * doorbell rings, and the response read from its RX half after its doorbell.
 * The driver flushes what it writes; the RX half is cacheable on this core,
 * so the D-cache is invalidated over the response before it is read.
 *
 * Each half has one owner at a time (aspeed_psp_ipc.h): REQUEST hands the
 * request buffer to the SSMCU, which hands it back with REQ_ACK once it has
 * copied the request out, and a RESPONSE with a message hands the response
 * buffer over until RSP_ACK, sent once it is copied out here, or at once
 * for a late response. A SYNC starts the channel; a missing ACK or a
 * timeout marks it unsynced, and the next request SYNCs first, so a buffer
 * is never written while the other side may still read it.
 *
 * "spdm send" in the shell forwards a request typed in by hand, for testing
 * the SSMCU side without a requester; "spdm stats" shows the counters.
 */

#include <stdlib.h>
#include <string.h>
#include <zephyr/cache.h>
#include <zephyr/drivers/ipm.h>
#include <zephyr/drivers/ipm_ast.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/barrier.h>
#include <zephyr/sys/util.h>
#include "aspeed_psp_ipc.h"
#include "mctp_eval.h"

LOG_MODULE_REGISTER(mctp_eval_spdm, CONFIG_MCTP_EVAL_LOG_LEVEL);

#define MCTP_MSG_TYPE_SPDM		0x05
#define MCTP_MSG_TYPE_SECURED_SPDM	0x06
#define SPDM_QUEUE_DEPTH		4
/* Descriptors the ISR can hold before the bridge thread reads them */
#define SPDM_EVT_QUEUE_DEPTH		8
#define SPDM_THREAD_STACK_SIZE		2048
#define SPDM_THREAD_PRIORITY		K_LOWEST_APPLICATION_THREAD_PRIO
#define SPDM_TIMEOUT			K_MSEC(CONFIG_MCTP_EVAL_SPDM_TIMEOUT_MS)
#define SPDM_ACK_TIMEOUT		K_MSEC(CONFIG_MCTP_EVAL_SPDM_ACK_TIMEOUT_MS)
#define SPDM_SYNC_TRIES			3
/* The SSMCU acknowledges a doorbell within its interrupt handler */
#define SPDM_SEND_RETRIES		10
#define SPDM_SHELL_MAX_LEN		64

/* The SSMCU expects the request buffer right before the response buffer */
BUILD_ASSERT(PSP_SPDM_RSP_OFFSET == PSP_SPDM_REQ_OFFSET + PSP_SPDM_BUF_SIZE);
BUILD_ASSERT(CONFIG_MCTP_MAX_MESSAGE_SIZE >= PSP_SPDM_MAX_MSG_SIZE,
	     "an SPDM response must fit one MCTP message");

static const struct device *const ipc = DEVICE_DT_GET(DT_NODELABEL(ipc0_cm4_ssmcu));

struct spdm_req {
	struct eval_bus *bus;
	uint8_t eid;
	uint8_t tag;
	uint16_t len;
	uint8_t msg[PSP_SPDM_MAX_MSG_SIZE];
};

K_MSGQ_DEFINE(spdm_queue, sizeof(struct spdm_req), SPDM_QUEUE_DEPTH, 4);

/* One request in flight on the channel, from the thread or the shell */
static K_MUTEX_DEFINE(forward_lock);
static uint32_t seq;
/* The SSMCU answered our last SYNC; forward_lock guards it */
static bool synced;
/*
 * Shell fault injection: act as if the SSMCU never answered the next request
 * (REQ_ACK and RESPONSE lost), or the next RSP_ACK were lost
 */
static bool lose_req_ack, lose_rsp_ack;

/*
 * Descriptors from the SSMCU on both IPIs, queued whole by the ISR in the
 * order it takes them: a late response to an abandoned request can't
 * overwrite the one being read, and is dropped on its own.
 */
K_MSGQ_DEFINE(evt_queue, sizeof(uint32_t[PSP_SPDM_DESC_WORDS]), SPDM_EVT_QUEUE_DEPTH, 4);

/*
 * Staging for the rx callbacks, which k_msgq_put() copies from: two buses'
 * callbacks can run at once, so rx_lock guards it.
 */
static K_MUTEX_DEFINE(rx_lock);
static struct spdm_req rx_staging;
static uint8_t thread_rsp[PSP_SPDM_MAX_MSG_SIZE];

static struct {
	uint32_t queued;
	uint32_t dropped;
	uint32_t answered;
	uint32_t rejected;
	uint32_t timeouts;
	uint32_t stale;
	uint32_t ack_timeouts;
	uint32_t syncs;
	uint32_t sync_failures;
	uint32_t evt_overflows;
	uint32_t tx_errors;
	uint32_t ack_max_us;
	uint32_t rtt_max_us;
	uint64_t rtt_sum_us;
} stats;

/* IPM ISR: the descriptor is copied before the driver acknowledges it */
static void spdm_ipc_cb(const struct device *dev, void *user_data, uint32_t id,
			volatile void *data)
{
	uint32_t desc[PSP_SPDM_DESC_WORDS];

	for (int i = 0; i < PSP_SPDM_DESC_WORDS; i++) {
		desc[i] = ((volatile uint32_t *)data)[i];
	}
	if (k_msgq_put(&evt_queue, desc, K_NO_WAIT)) {
		stats.evt_overflows++;
	}
}

/* Sends a descriptor; the SSMCU takes one within its interrupt handler */
static int spdm_send_desc(uint32_t ipi, const uint32_t *desc)
{
	int ret;

	for (int i = 0; i < SPDM_SEND_RETRIES; i++) {
		ret = ipm_send(ipc, 0, ipi, desc, PSP_SPDM_DESC_WORDS * sizeof(uint32_t));
		if (ret != -EBUSY) {
			break;
		}
		k_msleep(1);
	}
	if (ret) {
		stats.tx_errors++;
	}
	return ret;
}

/* Hands the response buffer back to the SSMCU */
static void spdm_rsp_ack(uint32_t rsp_seq)
{
	uint32_t desc[PSP_SPDM_DESC_WORDS] = {PSP_SPDM_OP_RSP_ACK, rsp_seq};

	if (lose_rsp_ack) {
		lose_rsp_ack = false;
		synced = false;
		return;
	}
	/* Until it has the buffer back, the SSMCU holds its responses */
	if (spdm_send_desc(PSP_SPDM_ACK_IPI, desc)) {
		synced = false;
	}
}

/* An event that isn't the one waited for: a late response is acknowledged */
static void spdm_stale(const uint32_t *desc)
{
	if (desc[PSP_SPDM_WORD_OP] != PSP_SPDM_OP_RESPONSE) {
		return;
	}
	stats.stale++;
	if (desc[PSP_SPDM_WORD_LEN]) {
		spdm_rsp_ack(desc[PSP_SPDM_WORD_SEQ]);
	}
}

/*
 * (Re)starts the channel: once the SSMCU answers, it holds no request and
 * no response, and reads nothing from the request buffer any more.
 */
static int spdm_sync(void)
{
	static bool version_logged;
	uint32_t desc[PSP_SPDM_DESC_WORDS] = {PSP_SPDM_OP_SYNC};
	uint32_t evt[PSP_SPDM_DESC_WORDS];
	int ret;

	desc[PSP_SPDM_WORD_VERSION] = PSP_SPDM_PROTO_VERSION;
	for (int i = 0; i < SPDM_SYNC_TRIES; i++) {
		k_timepoint_t end = sys_timepoint_calc(SPDM_ACK_TIMEOUT);

		desc[PSP_SPDM_WORD_SEQ] = ++seq;
		ret = spdm_send_desc(PSP_SPDM_ACK_IPI, desc);
		if (ret) {
			break;
		}
		while (!k_msgq_get(&evt_queue, evt, sys_timepoint_timeout(end))) {
			if (evt[PSP_SPDM_WORD_OP] != PSP_SPDM_OP_SYNC_ACK ||
			    evt[PSP_SPDM_WORD_SEQ] != seq) {
				spdm_stale(evt);
				continue;
			}
			if (evt[PSP_SPDM_WORD_STATUS] != PSP_SPDM_STATUS_OK) {
				if (!version_logged) {
					LOG_ERR("spdm: SSMCU doesn't take protocol version %u "
						"(status %u)", PSP_SPDM_PROTO_VERSION,
						evt[PSP_SPDM_WORD_STATUS]);
					version_logged = true;
				}
				stats.sync_failures++;
				return -EPROTONOSUPPORT;
			}
			stats.syncs++;
			synced = true;
			return 0;
		}
	}

	stats.sync_failures++;
	return ret ? ret : -ETIMEDOUT;
}

/*
 * Forwards one request and waits for its response. Returns 0 and the
 * response status, or a negative errno when no response came.
 */
static int spdm_forward(const uint8_t *msg, size_t len, uint8_t *rsp, size_t *rsp_len,
			uint32_t *status)
{
	uint32_t desc[PSP_SPDM_DESC_WORDS] = {0};
	uint32_t rsp_desc[PSP_SPDM_DESC_WORDS];
	k_timepoint_t ack_end, rsp_end;
	uint32_t start, rtt;
	bool acked = false, deaf;
	int ret;

	if (len == 0 || len > PSP_SPDM_MAX_MSG_SIZE) {
		return -EMSGSIZE;
	}

	k_mutex_lock(&forward_lock, K_FOREVER);

	if (!synced) {
		ret = spdm_sync();
		if (ret) {
			goto out;
		}
	}

	/* Late answers to abandoned requests: hand their buffers back */
	while (!k_msgq_get(&evt_queue, rsp_desc, K_NO_WAIT)) {
		spdm_stale(rsp_desc);
	}

	/* The request buffer is ours: the SSMCU acknowledged the last request */
	ret = ast_ipm_shmem_write(ipc, PSP_SPDM_IPI, 0, msg, len);
	if (ret < 0) {
		stats.tx_errors++;
		goto out;
	}
	barrier_dsync_fence_full();

	desc[PSP_SPDM_WORD_OP] = PSP_SPDM_OP_REQUEST;
	desc[PSP_SPDM_WORD_SEQ] = ++seq;
	desc[PSP_SPDM_WORD_OFFSET] = PSP_SPDM_REQ_OFFSET;
	desc[PSP_SPDM_WORD_LEN] = len;

	deaf = lose_req_ack;
	lose_req_ack = false;

	start = k_cycle_get_32();
	ack_end = sys_timepoint_calc(SPDM_ACK_TIMEOUT);
	rsp_end = sys_timepoint_calc(SPDM_TIMEOUT);
	ret = spdm_send_desc(PSP_SPDM_IPI, desc);
	if (ret) {
		goto out;
	}

	/*
	 * REQ_ACK, then the RESPONSE, which acknowledges the request too: the
	 * ISR may take the two IPIs in either order. Anything else, with an
	 * older number, answers an abandoned request.
	 */
	while (true) {
		ret = k_msgq_get(&evt_queue, rsp_desc,
				 sys_timepoint_timeout(acked ? rsp_end : ack_end));
		if (ret) {
			/* SYNC before the next request, whichever buffer is out */
			synced = false;
			if (acked) {
				stats.timeouts++;
			} else {
				stats.ack_timeouts++;
			}
			ret = -ETIMEDOUT;
			goto out;
		}
		if (rsp_desc[PSP_SPDM_WORD_SEQ] != seq) {
			spdm_stale(rsp_desc);
			continue;
		}
		if (deaf) {
			continue;
		}
		if (rsp_desc[PSP_SPDM_WORD_OP] == PSP_SPDM_OP_REQ_ACK) {
			acked = true;
			stats.ack_max_us = MAX(stats.ack_max_us,
					       k_cyc_to_us_near32(k_cycle_get_32() - start));
			if (rsp_desc[PSP_SPDM_WORD_STATUS] != PSP_SPDM_STATUS_OK) {
				/* Refused; no RESPONSE follows */
				break;
			}
			continue;
		}
		if (rsp_desc[PSP_SPDM_WORD_OP] == PSP_SPDM_OP_RESPONSE) {
			break;
		}
	}

	*status = rsp_desc[PSP_SPDM_WORD_STATUS];
	*rsp_len = 0;
	if (rsp_desc[PSP_SPDM_WORD_OP] == PSP_SPDM_OP_RESPONSE &&
	    *status == PSP_SPDM_STATUS_OK) {
		size_t n = rsp_desc[PSP_SPDM_WORD_LEN];
		void *body;

		if (rsp_desc[PSP_SPDM_WORD_OFFSET] != PSP_SPDM_RSP_OFFSET ||
		    n > PSP_SPDM_MAX_MSG_SIZE ||
		    ast_ipm_shmem_read(ipc, PSP_SPDM_IPI, 0, &body, n) < 0) {
			ret = -EBADMSG;
		} else {
			sys_cache_data_invd_range(body, ROUND_UP(n, CONFIG_DCACHE_LINE_SIZE));
			memcpy(rsp, body, n);
			*rsp_len = n;
			stats.answered++;
		}
		if (n) {
			spdm_rsp_ack(seq);
		}
		if (ret) {
			goto out;
		}
	} else {
		stats.rejected++;
	}

	rtt = k_cyc_to_us_near32(k_cycle_get_32() - start);
	stats.rtt_max_us = MAX(stats.rtt_max_us, rtt);
	stats.rtt_sum_us += rtt;

out:
	k_mutex_unlock(&forward_lock);
	return ret;
}

bool mctp_eval_spdm_rx(struct eval_bus *bus, uint8_t src_eid, bool tag_owner, uint8_t msg_tag,
		       const uint8_t *msg, size_t len)
{
	struct spdm_req *req = &rx_staging;

	if (len < 1 || ((msg[0] & MCTP_MSG_TYPE_MASK) != MCTP_MSG_TYPE_SPDM &&
			 (msg[0] & MCTP_MSG_TYPE_MASK) != MCTP_MSG_TYPE_SECURED_SPDM)) {
		return false;
	}

	/* We send no SPDM requests, so nothing answers us */
	if (!tag_owner) {
		return true;
	}

	if (len > PSP_SPDM_MAX_MSG_SIZE) {
		stats.dropped++;
		return true;
	}

	k_mutex_lock(&rx_lock, K_FOREVER);
	req->bus = bus;
	req->eid = src_eid;
	req->tag = msg_tag;
	req->len = len;
	memcpy(req->msg, msg, len);
	if (k_msgq_put(&spdm_queue, req, K_NO_WAIT)) {
		stats.dropped++;
	} else {
		stats.queued++;
	}
	k_mutex_unlock(&rx_lock);

	return true;
}

static void spdm_bridge_thread(void *p1, void *p2, void *p3)
{
	static struct spdm_req req;

	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	/* The SSMCU may not be up yet; the first request SYNCs again then */
	k_mutex_lock(&forward_lock, K_FOREVER);
	if (spdm_sync() == 0) {
		LOG_INF("spdm: SSMCU channel synced");
	}
	k_mutex_unlock(&forward_lock);

	while (true) {
		size_t rsp_len;
		uint32_t status;
		int ret;

		k_msgq_get(&spdm_queue, &req, K_FOREVER);

		ret = spdm_forward(req.msg, req.len, thread_rsp, &rsp_len, &status);
		if (ret) {
			LOG_WRN("spdm: request from eid 0x%02x not answered (%d)", req.eid, ret);
			continue;
		}
		if (status != PSP_SPDM_STATUS_OK) {
			LOG_WRN("spdm: SSMCU rejected request from eid 0x%02x (status %u)",
				req.eid, status);
			continue;
		}

		k_mutex_lock(req.bus->lock, K_FOREVER);
		ret = mctp_message_tx(req.bus->mctp, req.eid, false, req.tag, thread_rsp, rsp_len);
		k_mutex_unlock(req.bus->lock);
		if (ret) {
			stats.tx_errors++;
			LOG_ERR("spdm: %s response to eid 0x%02x failed (%d)", req.bus->name, req.eid,
				ret);
		}
	}
}

K_THREAD_DEFINE(spdm_bridge_tid, SPDM_THREAD_STACK_SIZE, spdm_bridge_thread, NULL, NULL, NULL,
		SPDM_THREAD_PRIORITY, 0, SYS_FOREVER_MS);

int mctp_eval_spdm_init(void)
{
	if (!device_is_ready(ipc)) {
		LOG_ERR("spdm: %s not ready", ipc->name);
		return -ENODEV;
	}

	/* Each half of the window holds one buffer */
	if (ast_ipm_max_tx_shmem_size(ipc, PSP_SPDM_IPI) < PSP_SPDM_BUF_SIZE ||
	    ast_ipm_max_rx_shmem_size(ipc, PSP_SPDM_IPI) < PSP_SPDM_BUF_SIZE) {
		LOG_ERR("spdm: %s has no %u-byte window on IPI%d", ipc->name,
			PSP_SPDM_BUF_SIZE, PSP_SPDM_IPI);
		return -ENOMEM;
	}

	ipm_register_id_callback(ipc, PSP_SPDM_IPI, spdm_ipc_cb, NULL);
	ipm_register_id_callback(ipc, PSP_SPDM_ACK_IPI, spdm_ipc_cb, NULL);
	ipm_set_id_enabled(ipc, PSP_SPDM_IPI, true);
	ipm_set_id_enabled(ipc, PSP_SPDM_ACK_IPI, true);
	k_thread_start(spdm_bridge_tid);
	LOG_INF("spdm: bridge to the SSMCU on %s IPI%d", ipc->name, PSP_SPDM_IPI);

	return 0;
}

int mctp_eval_spdm_bus_init(struct eval_bus *bus)
{
	int ret = mctp_control_add_type(bus->mctp, MCTP_MSG_TYPE_SPDM);

	if (ret) {
		return ret;
	}
	return mctp_control_add_type(bus->mctp, MCTP_MSG_TYPE_SECURED_SPDM);
}

/* spdm send <byte> ...: an SPDM message; the MCTP type byte is added */
static int cmd_spdm_send(const struct shell *sh, size_t argc, char **argv)
{
	static uint8_t req[1 + SPDM_SHELL_MAX_LEN];
	static uint8_t rsp[PSP_SPDM_MAX_MSG_SIZE];
	size_t len = argc - 1, rsp_len;
	uint32_t status, start;
	int ret;

	if (len > SPDM_SHELL_MAX_LEN) {
		shell_error(sh, "at most %d bytes", SPDM_SHELL_MAX_LEN);
		return -EINVAL;
	}

	req[0] = MCTP_MSG_TYPE_SPDM;
	for (size_t i = 0; i < len; i++) {
		req[1 + i] = strtoul(argv[1 + i], NULL, 16);
	}

	start = k_cycle_get_32();
	ret = spdm_forward(req, len + 1, rsp, &rsp_len, &status);
	if (ret) {
		shell_error(sh, "no response (%d)", ret);
		return ret;
	}

	shell_print(sh, "status %u, %zu bytes in %u us", status, rsp_len,
		    k_cyc_to_us_near32(k_cycle_get_32() - start));
	if (rsp_len) {
		shell_hexdump(sh, rsp, rsp_len);
	}

	return 0;
}

static int cmd_spdm_stats(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t done = stats.answered + stats.rejected;

	if (argc > 1 && !strcmp(argv[1], "reset")) {
		memset(&stats, 0, sizeof(stats));
		return 0;
	}

	shell_print(sh, "queued %u, dropped %u", stats.queued, stats.dropped);
	shell_print(sh, "answered %u, rejected %u, timeouts %u, stale %u, tx errors %u",
		    stats.answered, stats.rejected, stats.timeouts, stats.stale, stats.tx_errors);
	shell_print(sh, "channel %s: syncs %u, sync failures %u, ack timeouts %u, "
		    "event overflows %u, ack max %u us", synced ? "synced" : "unsynced",
		    stats.syncs, stats.sync_failures, stats.ack_timeouts, stats.evt_overflows,
		    stats.ack_max_us);
	if (done) {
		shell_print(sh, "SSMCU round trip: avg %u us, max %u us",
			    (uint32_t)(stats.rtt_sum_us / done), stats.rtt_max_us);
	}

	return 0;
}

/* spdm fault req-ack|rsp-ack: see lose_req_ack */
static int cmd_spdm_fault(const struct shell *sh, size_t argc, char **argv)
{
	k_mutex_lock(&forward_lock, K_FOREVER);
	if (!strcmp(argv[1], "req-ack")) {
		lose_req_ack = true;
	} else if (!strcmp(argv[1], "rsp-ack")) {
		lose_rsp_ack = true;
	} else {
		k_mutex_unlock(&forward_lock);
		shell_error(sh, "req-ack or rsp-ack");
		return -EINVAL;
	}
	k_mutex_unlock(&forward_lock);

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_spdm,
	SHELL_CMD_ARG(send, NULL, "Forward an SPDM message to the SSMCU: send <hex byte> ...",
		      cmd_spdm_send, 2, SPDM_SHELL_MAX_LEN - 1),
	SHELL_CMD_ARG(stats, NULL, "Bridge counters: stats [reset]", cmd_spdm_stats, 1, 1),
	SHELL_CMD_ARG(fault, NULL, "Lose the SSMCU's next REQ_ACK and RESPONSE, or our next "
		      "RSP_ACK: fault req-ack|rsp-ack",
		      cmd_spdm_fault, 2, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(spdm, &sub_spdm, "SPDM bridge to the SSMCU", NULL);
