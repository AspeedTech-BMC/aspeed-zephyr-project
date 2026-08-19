/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "mctp.h"
#include "mctp_i3c.h"
#include "gpio/gpio_aspeed.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "AspeedStateMachine/AspeedStateMachine.h"

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
#include "SPDM/SPDMRequester.h"
#endif

LOG_MODULE_REGISTER(mctp_i3c_target_state, LOG_LEVEL_INF);

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
void mctp_i3c_pre_attestation(struct device_manager *mgr, int *duration)
{
	uint8_t provision_state = GetUfmStatusValue();

	if (provision_state & UFM_PROVISIONED) {
		if (is_pltrst_sync())
			device_manager_update_device_state(mgr,
					DEVICE_MANAGER_SELF_DEVICE_NUM,
					DEVICE_MANAGER_ATTESTATION);
	} else if (is_pltrst_sync()) {
		device_manager_update_device_state(mgr,
				DEVICE_MANAGER_SELF_DEVICE_NUM,
				DEVICE_MANAGER_RUNTIME);
	}
	*duration = 1;
}

void mctp_i3c_attestation(struct device_manager *mgr, int *duration)
{
	uint32_t event = spdm_get_attester();

	if (!(event & SPDM_REQ_EVT_ENABLE)) {
		device_manager_update_device_state(mgr,
				DEVICE_MANAGER_SELF_DEVICE_NUM,
				DEVICE_MANAGER_RUNTIME);
	} else if (!(event & SPDM_REQ_EVT_T0_I3C)) {
		spdm_run_attester_i3c();
		*duration = 10;
	} else if (!(event & SPDM_REQ_EVT_ATTESTED_CPU)) {
		*duration = 10;
	} else {
		device_manager_update_device_state(mgr,
				DEVICE_MANAGER_SELF_DEVICE_NUM,
				DEVICE_MANAGER_RUNTIME);
	}
}
#endif

static void mctp_i3c_target_state_handler(void *arg, void *unused1, void *unused2)
{
	mctp_i3c *instance = arg;
	mctp *mctp_instance = instance->mctp_inst;
	struct device_manager *mgr =
		mctp_instance->mctp_wrapper.mctp_interface.device_manager;
	int duration = MCTP_I3C_MSG_RETRY_INTERVAL;

	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);

	while (1) {
		int state;

		k_sem_take(&instance->i3c_state_sem, K_FOREVER);
		state = device_manager_get_device_state(mgr,
				DEVICE_MANAGER_SELF_DEVICE_NUM);
		if (state == DEVICE_MANAGER_SEND_DISCOVERY_NOTIFY) {
			mctp_i3c_send_discovery_notify(mctp_instance, &duration);
		} else if (state == DEVICE_MANAGER_EID_ANNOUNCEMENT) {
			mctp_i3c_send_eid_announcement(mctp_instance, &duration);
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
		} else if (state == DEVICE_MANAGER_PRE_ATTESTATION) {
			mctp_i3c_pre_attestation(mgr, &duration);
		} else if (state == DEVICE_MANAGER_ATTESTATION) {
			mctp_i3c_attestation(mgr, &duration);
		} else if (state == DEVICE_MANAGER_RUNTIME) {
			if (is_pltrst_sync())
				RSTPlatformReset(false);
			duration = 0;
#endif
		} else {
			duration = 0;
		}

		if (duration > 0 && instance->state == MCTP_I3C_TARGET_ATTACHED) {
			k_timer_start(&instance->i3c_state_timer,
					K_SECONDS(duration), K_NO_WAIT);
		}
	}
}

uint8_t mctp_i3c_eid_assignment_thread_create(mctp_i3c *instance)
{
	instance->i3c_state_tid = k_thread_create(&instance->i3c_state_thread,
			instance->i3c_state_handler_stack,
			MCTP_I3C_STATE_HANDLER_STACK_SIZE,
			mctp_i3c_target_state_handler, instance, NULL, NULL,
			5, 0, K_NO_WAIT);
	if (!instance->i3c_state_tid)
		return MCTP_ERROR;

	snprintf(instance->i3c_state_task_name,
		 sizeof(instance->i3c_state_task_name),
		 "MCTP I3C Target B%02xA%02x",
		 instance->mctp_inst->medium_conf.i3c_conf.bus,
		 instance->mctp_inst->medium_conf.i3c_conf.addr);
	k_thread_name_set(instance->i3c_state_tid,
			  instance->i3c_state_task_name);

	return MCTP_SUCCESS;
}
