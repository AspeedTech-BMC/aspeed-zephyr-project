/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "mctp.h"
#include "mctp_i3c.h"
#include "mctp_i3c_role.h"
#include "mctp/mctp_base_protocol.h"

LOG_MODULE_REGISTER(mctp_i3c_common, LOG_LEVEL_INF);

#define MCTP_DOE_REGISTRATION_CMD 0x4

static uint8_t mctp_msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN];

void mctp_i3c_stop_discovery_notify(struct device_manager *mgr)
{
	int status = device_manager_update_device_state(mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM,
			DEVICE_MANAGER_EID_ANNOUNCEMENT);

	if (status != 0)
		LOG_ERR("update self device state failed");

	LOG_INF("PFR EID %02x is assigned by bus owner",
		device_manager_get_device_eid(mgr, DEVICE_MANAGER_SELF_DEVICE_NUM));
}

int mctp_i3c_send_discovery_notify(mctp *mctp_instance, int *duration)
{
	struct mctp_interface *interface =
		&mctp_instance->mctp_wrapper.mctp_interface;
	uint8_t req_buf[] = {
		MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, 0x81, 0x0d,
	};

	mctp_interface_issue_request(interface,
			&mctp_instance->mctp_cmd_channel,
			mctp_instance->medium_conf.i3c_conf.addr, 0,
			req_buf, sizeof(req_buf), mctp_msg_buf,
			sizeof(mctp_msg_buf), 1);
	*duration = MCTP_I3C_MSG_RETRY_INTERVAL;

	return 0;
}

int mctp_i3c_send_eid_announcement(mctp *mctp_instance, int *duration)
{
	struct mctp_interface *interface =
		&mctp_instance->mctp_wrapper.mctp_interface;
	struct device_manager *mgr = interface->device_manager;
	uint8_t dest_eid;
	int src_eid;
	int status = -1;

	if (mctp_i3c_role.resolve_dest_eid(mctp_instance, &dest_eid))
		return status;

	src_eid = device_manager_get_device_eid(mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM);
	if (ROT_IS_ERROR(src_eid)) {
		LOG_ERR("Failed to get self EID");
		return status;
	}

	uint8_t req_buf[] = {
		MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, 0x80, 0x86, 0x80,
		0x0a, 0x00, 0x00, 0x00, 0x00, MCTP_DOE_REGISTRATION_CMD,
		0x00, 0x00, 0x01, (uint8_t)src_eid, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00,
	};

	status = mctp_interface_issue_request(interface,
			&mctp_instance->mctp_cmd_channel,
			mctp_instance->medium_conf.i3c_conf.addr, dest_eid,
			req_buf, sizeof(req_buf), mctp_msg_buf,
			sizeof(mctp_msg_buf), 12000);
	if (status == 0) {
		device_manager_update_device_state(mgr,
				DEVICE_MANAGER_SELF_DEVICE_NUM,
				DEVICE_MANAGER_PRE_ATTESTATION);
	}
	*duration = 2;

	return status;
}

void mctp_i3c_state_expiry_fn(struct k_timer *timer)
{
	struct k_sem *sem = k_timer_user_data_get(timer);

	k_sem_give(sem);
}
