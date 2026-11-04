/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LSTP_TRANSACTION_H
#define LSTP_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>
#include <zephyr/kernel.h>

#include "lstp_common.h"

#ifdef CONFIG_OBMF_LSTP_MTD_CLIENT
void lstp_transaction_init(void);
int lstp_transaction_request(uint8_t channel_id, uint8_t command,
			     const void *request, size_t request_len,
			     void *response, size_t response_capacity,
			     size_t *response_len, lstp_status_t *response_status,
			     k_timeout_t timeout);
bool lstp_transaction_handle_response(const uint8_t *packet, size_t len);
void lstp_transaction_transport_reset(void);
#else
static inline void lstp_transaction_init(void) {}
static inline void lstp_transaction_transport_reset(void) {}
static inline bool lstp_transaction_handle_response(const uint8_t *packet, size_t len)
{
	ARG_UNUSED(packet);
	ARG_UNUSED(len);
	return false;
}
#endif

#endif /* LSTP_TRANSACTION_H */
