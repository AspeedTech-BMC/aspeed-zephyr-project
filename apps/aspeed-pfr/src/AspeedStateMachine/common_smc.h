/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once


/* List of HRoT states */
enum HRoT_state { IDLE, INITIALIZE, I2C, VERIFY, RECOVERY, UPDATE, LOCKDOWN };

typedef enum {
	Success,
	Failure,
	ManifestCorruption,
	VerifyRecovery,
	VerifyActive,
	UnSupported,
	Decommission_Success,
	Lockdown
} Verification_Status;

enum _hrot_event {
	BMC_EVENT = 1,
	PCH_EVENT,
	I2C_EVENT
};

