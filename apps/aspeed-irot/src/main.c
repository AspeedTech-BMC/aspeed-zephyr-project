/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <state_machine/irot_fsm.h>

LOG_MODULE_REGISTER(aspeed_irot);

int main() {
	k_msleep(1000);  // Wait for system stabilization
	LOG_INF("Aspeed IROT module initialized.");

	irot_send_event(INIT_DONE, NULL);
	irot_send_event(VERIFY_DONE, NULL);
	irot_send_event(ARMING_DONE, NULL);

	return 0;
}

