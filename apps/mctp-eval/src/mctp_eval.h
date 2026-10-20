/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef MCTP_EVAL_H_
#define MCTP_EVAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <zephyr/kernel.h>
#include <libmctp.h>

#define MCTP_MSG_TYPE_MASK	0x7f
#define MCTP_MSG_TYPE_PLDM	0x01

/*
 * One transport and its libmctp instance, NULL if the bus failed to start.
 * libmctp is not thread-safe: every call into a bus's mctp is made with its
 * lock held.
 */
struct eval_bus {
	const char *name;
	struct mctp *mctp;
	struct k_mutex *lock;
	/* The binding's count of packets it dropped, updated under lock */
	const uint32_t *tx_errors;
};

/* Next message tag for a request we originate */
uint8_t mctp_eval_next_tag(void);

#ifdef CONFIG_MCTP_EVAL_PLDM
int mctp_eval_pldm_init(void);
/* Advertise PLDM in the bus's Get Message Type Support response */
int mctp_eval_pldm_bus_init(struct eval_bus *bus);
/*
 * Called from the bus rx callback with the bus lock held; true if the
 * message was PLDM (and has been handled).
 */
bool mctp_eval_pldm_rx(struct eval_bus *bus, uint8_t src_eid, bool tag_owner, uint8_t msg_tag,
		       const uint8_t *msg, size_t len);
#endif

#ifdef CONFIG_MCTP_EVAL_SPDM_BRIDGE
int mctp_eval_spdm_init(void);
/* Advertise SPDM and secured SPDM in the bus's Get Message Type Support response */
int mctp_eval_spdm_bus_init(struct eval_bus *bus);
/*
 * Called from the bus rx callback with the bus lock held; true if the
 * message was SPDM or secured SPDM (and has been queued for the SSMCU).
 */
bool mctp_eval_spdm_rx(struct eval_bus *bus, uint8_t src_eid, bool tag_owner, uint8_t msg_tag,
		       const uint8_t *msg, size_t len);
#endif

#endif /* MCTP_EVAL_H_ */
