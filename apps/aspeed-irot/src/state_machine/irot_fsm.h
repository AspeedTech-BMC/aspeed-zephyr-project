/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

enum IROT_STATE {
	INIT, VERIFY, ARMING, RUNTIME, UPDATE, DISARM, DEINIT, PANIC, REBOOT,
};

enum IROT_EVENT {
	INIT_DONE, INIT_FAILED,
	VERIFY_DONE, VERIFY_FAILED, VERIFY_SKIPED,
	ARMING_DONE, ARMING_FAILED,
	UPDATE_REQUESTED, 
	UPDATE_COMPLETED, UPDATE_FAILED,

};

struct irot_event_msg {
	enum IROT_EVENT event;
	void *data;
};

extern void irot_send_event(enum IROT_EVENT event, void *data);

