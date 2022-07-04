/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once
#include <zephyr.h>
#include <StateMachineAction/StateMachineActions.h>

enum aspeed_pfr_state {
	BOOT,
	INIT,
	UNPROVISIONED,
	ROT_RECOVERY,
	TMIN1,
	TZERO,
	FIRMWARE_VERIFY,
	FIRMWARE_RECOVERY,
	FIRMWARE_UPDATE,
	RUNTIME,
	SYSTEM_LOCKDOWN,
	SYSTEM_REBOOT,
};

enum aspeed_pfr_event {
	START_STATE_MACHINE,
	INIT_DONE,
	INIT_ROT_SECONDARY_BOOTED,
	VERIFY_UNPROVISIONED,
	VERIFY_STG_FAILED,
	VERIFY_RCV_FAILED,
	VERIFY_ACT_FAILED,
	VERIFY_DONE,
	RECOVERY_FAILED,
	RECOVERY_DONE,
	RESET_DETECTED,
	UPDATE_REQUESTED,
	WDT_CHECKPOINT,
	WDT_TIMEOUT,
	UPDATE_DONE,
	UPDATE_FAILED,
	PROVISION_CMD,
};

union aspeed_event_data {
	/* Data in-place */
	uint32_t bit32;
	uint8_t bit8[4];

	/* Data somewhere else */
	uint8_t *ptr_u8;
	uint32_t *ptr_u32;
	void *ptr;
};

struct event_context {
	/* Reserved for FIFO */
	void *fifo_reserved;

	/* User Defined Event */
	enum aspeed_pfr_event event;
	union aspeed_event_data data;
};

struct smf_context {
	/* Context data for smf */
	struct smf_ctx ctx;

	/* User Define State Data */

	/* Input event, malloc by generator, release by state machine */
	struct event_context *event_ctx;

	/* Firmware state */
	AO_DATA bmc_active_object;
	AO_DATA pch_active_object;
};

extern struct k_fifo aspeed_sm_fifo;

void GenerateStateMachineEvent(enum aspeed_pfr_event evt, void *data);
void AspeedStateMachine(void);
