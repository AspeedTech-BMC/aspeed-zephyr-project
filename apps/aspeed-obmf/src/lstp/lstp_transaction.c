/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "lstp_backend.h"
#include "lstp_transaction.h"
#include "lstp_usb.h"

LOG_MODULE_REGISTER(lstp_transaction, LOG_LEVEL_WRN);

/* Up to this many 1 ms waits for room in the USB event queue. */
#define LSTP_TRANSACTION_SEND_RETRIES 100

struct lstp_sync_transaction {
	struct k_mutex request_lock;
	struct k_spinlock state_lock;
	struct k_sem completion;
	uint8_t packet[LSTP_MSG_SIZE];
	uint8_t response[LSTP_MAX_PAYLOAD_SIZE];
	size_t response_len;
	int transport_result;
	lstp_status_t response_status;
	bool pending;
	bool completed;
	bool stale_response_expected;
	bool quarantine_warned;
	uint8_t channel_id;
};

static struct lstp_sync_transaction spi_transaction = { .channel_id = LSTP_SPI_CHANNEL_ID };

void lstp_transaction_init(void)
{
	k_mutex_init(&spi_transaction.request_lock);
	k_sem_init(&spi_transaction.completion, 0, 1);
}

int lstp_transaction_request(uint8_t channel_id, uint8_t command,
			     const void *request, size_t request_len,
			     void *response, size_t response_capacity,
			     size_t *response_len, lstp_status_t *response_status,
			     k_timeout_t timeout)
{
	struct lstp_sync_transaction *state = &spi_transaction;
	struct lstp_hdr *hdr;
	k_spinlock_key_t key;
	size_t received_len;
	uint32_t session;
	int ret;

	if (k_is_in_isr() || channel_id != state->channel_id ||
	    (command & LSTP_RESPONSE_BIT) != 0U ||
	    request_len > LSTP_MAX_PAYLOAD_SIZE ||
	    (request_len != 0U && request == NULL) ||
	    (response_capacity != 0U && response == NULL)) {
		return -EINVAL;
	}

	k_mutex_lock(&state->request_lock, K_FOREVER);
	k_sem_reset(&state->completion);

	key = k_spin_lock(&state->state_lock);
	/*
	 * LSTP replies carry no tag, so a timed-out request's late reply would be
	 * taken as the next request's (wrong data returned as success), and the
	 * timed-out request may still be sitting in the USB queue. So the channel
	 * stays blocked until that reply arrives or the USB transport resets
	 * (which drops the queue); there is no time-based expiry.
	 */
	if (state->stale_response_expected) {
		bool warn = !state->quarantine_warned;

		state->quarantine_warned = true;
		k_spin_unlock(&state->state_lock, key);
		if (warn) {
			LOG_WRN("Firmware-initiated SPI requests blocked until peer answers or USB resets");
		}
		k_mutex_unlock(&state->request_lock);
		return -EAGAIN;
	}
	k_spin_unlock(&state->state_lock, key);

	hdr = (struct lstp_hdr *)state->packet;
	hdr->channel_id = channel_id;
	hdr->cmd_status_code = command;
	hdr->len_lsb = request_len & LSB_MASK;
	hdr->len_msb = (request_len >> BYTE1_SHIFT) & LSB_MASK;
	if (request_len != 0U) {
		memcpy(state->packet + sizeof(*hdr), request, request_len);
	}

	key = k_spin_lock(&state->state_lock);
	session = lstp_usb_session();
	state->response_len = 0U;
	state->transport_result = 0;
	state->response_status = LSTP_STATUS_ERROR;
	state->completed = false;
	state->pending = true;
	k_spin_unlock(&state->state_lock, key);

	/* The event queue fills under UART bursts; wait for room instead of failing. */
	for (int tries = 0; ; tries++) {
		ret = lstp_usb_send_event_in(session, state->packet, sizeof(*hdr) + request_len);
		if (ret != -ENOSPC || tries >= LSTP_TRANSACTION_SEND_RETRIES) {
			break;
		}
		k_sleep(K_MSEC(1));
	}
	if (ret != 0) {
		key = k_spin_lock(&state->state_lock);
		state->pending = false;
		k_spin_unlock(&state->state_lock, key);
		goto out_unlock;
	}

	key = k_spin_lock(&state->state_lock);
	if (session != lstp_usb_session() ||
	    (state->completed && state->transport_result != 0)) {
		/* Reset drops queued packets tagged with the old session. */
		state->pending = false;
		state->completed = false;
		ret = -ENODEV;
		k_spin_unlock(&state->state_lock, key);
		goto out_unlock;
	}
	k_spin_unlock(&state->state_lock, key);

	ret = k_sem_take(&state->completion, timeout);
	key = k_spin_lock(&state->state_lock);
	if (ret != 0 && !state->completed) {
		state->pending = false;
		state->stale_response_expected = true;
		k_spin_unlock(&state->state_lock, key);
		ret = -ETIMEDOUT;
		goto out_unlock;
	}

	ret = state->transport_result;
	received_len = state->response_len;
	if (ret == 0 && received_len > response_capacity) {
		ret = -EMSGSIZE;
	}
	if (ret == 0 && received_len != 0U) {
		memcpy(response, state->response, received_len);
	}
	if (response_len != NULL) {
		*response_len = received_len;
	}
	if (response_status != NULL) {
		*response_status = state->response_status;
	}
	state->completed = false;
	k_spin_unlock(&state->state_lock, key);

out_unlock:
	k_mutex_unlock(&state->request_lock);
	return ret;
}

bool lstp_transaction_handle_response(const uint8_t *packet, size_t len)
{
	const struct lstp_hdr *hdr = (const struct lstp_hdr *)packet;
	size_t payload_len;

	if (packet == NULL || len < sizeof(*hdr) ||
	    (hdr->cmd_status_code & LSTP_RESPONSE_BIT) == 0U) {
		return false;
	}

	payload_len = hdr->len_lsb | (hdr->len_msb << BYTE1_SHIFT);
	if (payload_len > LSTP_MAX_PAYLOAD_SIZE ||
	    len < sizeof(*hdr) + payload_len) {
		return false;
	}

	if (hdr->channel_id == spi_transaction.channel_id) {
		struct lstp_sync_transaction *sync = &spi_transaction;
		k_spinlock_key_t key;
		bool signal = false;
		bool consumed = false;

		key = k_spin_lock(&sync->state_lock);
		if (sync->pending) {
			memcpy(sync->response, packet + sizeof(*hdr), payload_len);
			sync->response_len = payload_len;
			sync->response_status =
				(lstp_status_t)(hdr->cmd_status_code & ~LSTP_RESPONSE_BIT);
			sync->transport_result = 0;
			sync->pending = false;
			sync->completed = true;
			signal = true;
			consumed = true;
		} else if (sync->stale_response_expected) {
			sync->stale_response_expected = false;
			sync->quarantine_warned = false;
			consumed = true;
		}
		k_spin_unlock(&sync->state_lock, key);

		if (signal) {
			k_sem_give(&sync->completion);
		}
		return consumed;
	}

	return false;
}

void lstp_transaction_transport_reset(void)
{
	struct lstp_sync_transaction *state = &spi_transaction;
	k_spinlock_key_t key;
	bool signal = false;

	key = k_spin_lock(&state->state_lock);
	state->stale_response_expected = false;
	state->quarantine_warned = false;
	if (state->pending) {
		state->pending = false;
		state->completed = true;
		state->transport_result = -ENODEV;
		signal = true;
	}
	k_spin_unlock(&state->state_lock, key);

	if (signal) {
		k_sem_give(&state->completion);
	}
}
