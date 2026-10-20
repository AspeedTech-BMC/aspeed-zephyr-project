/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <mctp_req_worker.h>

LOG_MODULE_REGISTER(mctp_req_worker, LOG_LEVEL_INF);

static void release_buf(const struct mctp_req_worker *worker,
			uint8_t *buf)
{
	int rc = k_msgq_put(worker->free_bufs, &buf, K_NO_WAIT);

	/* Each checked-out buffer is returned exactly once. */
	if (rc != 0) {
		LOG_ERR("%s: failed to return buffer (RC %d)",
			worker->name, rc);
	}
}

int mctp_req_worker_pool_init(const struct mctp_req_worker *worker)
{
	uint8_t *buf;
	int rc;

	for (size_t i = 0; i < worker->buf_count; i++) {
		buf = malloc(worker->buf_size);
		if (buf == NULL) {
			rc = -ENOMEM;
			goto error;
		}

		rc = k_msgq_put(worker->free_bufs, &buf, K_NO_WAIT);
		if (rc != 0) {
			free(buf);
			goto error;
		}
	}

	return 0;

error:
	LOG_ERR("%s: failed to init buffer pool (RC %d)",
		worker->name, rc);
	while (k_msgq_get(worker->free_bufs, &buf, K_NO_WAIT) == 0) {
		free(buf);
	}
	return rc;
}

uint8_t mctp_req_worker_dispatch(const struct mctp_req_worker *worker,
			       void *mctp_p, uint8_t *buf,
			       uint32_t len,
			       mctp_ext_params ext_params)
{
	struct mctp_req_msg message = {0};
	int rc;

	if (mctp_p == NULL || buf == NULL || len == 0) {
		return MCTP_ERROR;
	}

	if (len > worker->buf_size) {
		LOG_WRN("%s: request length %u too long; dropped",
			worker->name, len);
		return MCTP_ERROR;
	}

	rc = k_msgq_get(worker->free_bufs, &message.buf, K_NO_WAIT);
	if (rc != 0) {
		LOG_WRN("%s: no free buffer; request dropped",
			worker->name);
		return MCTP_ERROR;
	}

	/* RX frees its original buffer when this callback returns. */
	memcpy(message.buf, buf, len);
	message.mctp_inst = (mctp *)mctp_p;
	message.len = len;
	message.ext_params = ext_params;

	rc = k_msgq_put(worker->queue, &message, K_NO_WAIT);
	if (rc != 0) {
		release_buf(worker, message.buf);
		LOG_WRN("%s: queue full; request dropped (RC %d)",
			worker->name, rc);
		return MCTP_ERROR;
	}

	return MCTP_SUCCESS;
}

void mctp_req_worker_run(const struct mctp_req_worker *worker)
{
	struct mctp_req_msg message;
	uint8_t ret;
	int rc;

	while (1) {
		rc = k_msgq_get(worker->queue, &message, K_FOREVER);
		if (rc != 0) {
			continue;
		}

		rc = mctp_validate_inst(message.mctp_inst);
		if (rc != 0) {
			LOG_WRN("%s: unknown MCTP inst %p (RC %d)",
				worker->name,
				(void *)message.mctp_inst, rc);
		} else {
			ret = worker->handler(message.mctp_inst,
					      message.buf,
					      message.len,
					      message.ext_params);
			if (ret != 0) {
				LOG_WRN("%s: request failed (RC %u)",
					worker->name, ret);
			}
		}

		release_buf(worker, message.buf);
	}
}
