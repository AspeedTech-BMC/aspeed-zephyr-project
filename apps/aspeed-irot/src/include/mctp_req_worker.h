/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <mctp.h>

/* Settings shared by the PLDM, SPDM and Composite EAT workers. */
#define MCTP_REQ_WORKER_QUEUE_SIZE 4
/* Largest request queued to a worker, PLDM_MAX_DATA_SIZE for PLDM. */
#define MCTP_REQ_WORKER_BUF_SIZE 4096
/*
 * Workers run below the MCTP RX/TX threads (priority 1), so RX and TX
 * can still receive and send packets while a handler is busy.
 */
#define MCTP_REQ_WORKER_PRIORITY 2
#define MCTP_REQ_WORKER_STACK_SIZE 16384

struct mctp_req_msg {
	mctp *mctp_inst;
	uint8_t *buf;
	uint32_t len;
	mctp_ext_params ext_params;
};

/*
 * A worker thread that handles one kind of incoming MCTP request
 * outside the MCTP RX thread. Requests are copied into a fixed pool
 * of buffers, so RX can keep receiving while a handler runs.
 */
struct mctp_req_worker {
	const char *name;
	mctp_fn_cb handler;
	struct k_msgq *queue;
	struct k_msgq *free_bufs;
	size_t buf_size;
	size_t buf_count;
};

int mctp_req_worker_pool_init(const struct mctp_req_worker *worker);
void mctp_req_worker_run(const struct mctp_req_worker *worker);

/* Called from MCTP RX: copy the request and queue it. */
uint8_t mctp_req_worker_dispatch(const struct mctp_req_worker *worker,
			       void *mctp_p, uint8_t *buf,
			       uint32_t len,
			       mctp_ext_params ext_params);

#define MCTP_REQ_WORKER_DEFINE(_name, _handler, _count, _size,   \
			       _stack, _prio)                    \
	K_MSGQ_DEFINE(_name##_queue, sizeof(struct mctp_req_msg), \
		      _count, 4);                                \
	K_MSGQ_DEFINE(_name##_free_bufs, sizeof(uint8_t *),      \
		      _count, 4);                                \
	static const struct mctp_req_worker _name = {            \
		.name = #_name,                                  \
		.handler = _handler,                             \
		.queue = &_name##_queue,                         \
		.free_bufs = &_name##_free_bufs,                 \
		.buf_size = _size,                               \
		.buf_count = _count,                             \
	};                                                       \
	static int _name##_pool_init(void)                       \
	{                                                        \
		return mctp_req_worker_pool_init(&_name);        \
	}                                                        \
	/* Fill the pool before static threads start. */         \
	SYS_INIT(_name##_pool_init, APPLICATION,                 \
		 CONFIG_APPLICATION_INIT_PRIORITY);              \
	static void _name##_entry(void *p1, void *p2, void *p3)  \
	{                                                        \
		ARG_UNUSED(p1);                                  \
		ARG_UNUSED(p2);                                  \
		ARG_UNUSED(p3);                                  \
		mctp_req_worker_run(&_name);                     \
	}                                                        \
	K_THREAD_DEFINE(_name##_tid, _stack, _name##_entry,      \
			NULL, NULL, NULL, _prio, 0, 0)
