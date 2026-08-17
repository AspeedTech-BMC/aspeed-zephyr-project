/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_PFR_MCTP)
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include "cmd_interface/device_manager.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/cmd_interface_system.h"
#include "mctp/mctp_base_protocol.h"
#include "mctp/cmd_interface_mctp_control.h"
#include "mctp/mctp_control_protocol.h"
#include "mctp/mctp_control_protocol_commands.h"
#include "mctp_interface_wrapper.h"

extern int device_manager_update_not_attestable_device_entry (struct device_manager *mgr, int device_num,
	uint8_t eid, uint8_t smbus_addr, uint8_t pcd_component_index);
#define NOT_USED 0 // currently, pcd_component_index doesn't have any functionality in code, to set it to zero

LOG_MODULE_REGISTER(mctp_interface_wrapper, CONFIG_LOG_DEFAULT_LEVEL);

#if defined(CONFIG_PFR_PLDM_FW_UPDATE)
#define MCTP_BASE_PROTOCOL_MSG_TYPE_PLDM 0x01

static int (*mctp_control_process_request)(struct cmd_interface *intf,
	struct cmd_interface_msg *request);

static int pfr_mctp_control_process_request(struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	struct mctp_control_protocol_header *header;
	struct mctp_control_get_message_type_response *response;
	uint8_t *types;
	bool get_message_types = false;
	int status;

	if ((request != NULL) &&
	    (request->length >= sizeof(struct mctp_control_protocol_header))) {
		header = (struct mctp_control_protocol_header *)request->data;
		get_message_types = (header->command_code ==
			MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE) && header->rq;
	}

	status = mctp_control_process_request(intf, request);
	if ((status != 0) || !get_message_types)
		return status;

	response = (struct mctp_control_get_message_type_response *)request->data;
	if (response->header.completion_code != MCTP_CONTROL_PROTOCOL_SUCCESS)
		return status;

	types = mctp_control_get_message_type_response_get_entries(response);
	types[response->message_type_count++] = MCTP_BASE_PROTOCOL_MSG_TYPE_PLDM;
	request->length = mctp_control_get_message_type_response_length(
		response->message_type_count);

	return status;
}

static void pfr_mctp_enable_pldm_type(struct cmd_interface_mctp_control *control)
{
	mctp_control_process_request = control->base.process_request;
	control->base.process_request = pfr_mctp_control_process_request;
}
#endif

/**
 * Helper function to setup the MCTP interface
 *
 * @param mctp The instances to initialize.
 *
 */
int mctp_interface_wrapper_init(struct mctp_interface_wrapper *mctp_wrapper, uint8_t rot_addr)
{
	if (mctp_wrapper == NULL)
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;

	int status;

	status = device_manager_init(&mctp_wrapper->device_mgr, 2, 0, DEVICE_MANAGER_PA_ROT_MODE,
			DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE, 1000, 0, 0, 0, 0, 0, 0);

	if (status != 0) {
		LOG_ERR("device manager init failed");
		return status;
	}

	status = device_manager_update_not_attestable_device_entry(&mctp_wrapper->device_mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, rot_addr, NOT_USED);
	if (status != 0) {
		LOG_ERR("update self device failed");
		return status;
	}

	status = device_manager_update_not_attestable_device_entry(&mctp_wrapper->device_mgr,
			DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM, MCTP_BASE_PROTOCOL_BMC_EID, 0x10, NOT_USED);
	if (status != 0) {
		LOG_ERR("update bridge device failed");
		return status;
	}

	status = cmd_interface_mctp_control_init(&mctp_wrapper->cmd_mctp_control, &mctp_wrapper->device_mgr,
			0x1414, 0x04);
	if (status != 0) {
		LOG_ERR("mctp control command interface init failed");
		goto error_device_mgr;
	}
#if defined(CONFIG_PFR_PLDM_FW_UPDATE)
	pfr_mctp_enable_pldm_type(&mctp_wrapper->cmd_mctp_control);
#endif

	// TODO: if wants to fully support cerberus system commands,
	// it should be changed to init cerberus protocol command cmd_interface_system_init.
	// However, its code size is very large. Only support mctp control commands.
	// mctp->cmd_cerberus.process_request = cmd_interface_system_process_request;
	// mctp->cmd_cerberus.process_response = cmd_interface_system_process_response;
	mctp_wrapper->cmd_cerberus.process_request = cmd_interface_system_process_request;
#if defined(CONFIG_PFR_SPDM_RESPONDER)
	mctp_wrapper->cmd_cerberus.process_response = cmd_interface_system_process_response;
#endif
	mctp_wrapper->cmd_cerberus.generate_error_packet = cmd_interface_generate_error_packet;

	status = mctp_interface_init(&mctp_wrapper->mctp_interface, &mctp_wrapper->cmd_cerberus,
			&mctp_wrapper->cmd_mctp_control.base, NULL, &mctp_wrapper->device_mgr);
	if (status != 0) {
		LOG_ERR("mctp interface init failed");
		goto error_cmd_interface;
	}

	return 0;

error_cmd_interface:
	cmd_interface_mctp_control_deinit(&mctp_wrapper->cmd_mctp_control);
error_device_mgr:
	device_manager_release(&mctp_wrapper->device_mgr);

	return status;
}

int mctp_i3c_wrapper_init(struct mctp_interface_wrapper *mctp_wrapper, uint8_t rot_addr)
{
	if (mctp_wrapper == NULL)
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;

	int status;
	struct device_manager *device_mgr = &mctp_wrapper->device_mgr;

	status = device_manager_init(device_mgr, 2, 0, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_I3C_SLAVE_BUS_ROLE, 1000, 0, 0, 0, 0, 0, 0);
	if (status != 0) {
		LOG_ERR("device manager init failed");
		return status;
	}

	status = device_manager_update_not_attestable_device_entry(device_mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM, MCTP_BASE_PROTOCOL_NULL_EID, 0, NOT_USED);
	if (status != 0) {
		LOG_ERR("update self device failed");
		return status;
	}

	// Send discovery notify after BMC bootup
	status = device_manager_update_device_state(device_mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM, DEVICE_MANAGER_SEND_DISCOVERY_NOTIFY);
	if (status != 0) {
		LOG_ERR("update self device state failed");
		return status;
	}

	status = device_manager_update_not_attestable_device_entry(device_mgr,
			DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM, MCTP_BASE_PROTOCOL_NULL_EID, 0, NOT_USED);
	if (status != 0) {
		LOG_ERR("update self device failed");
		return status;
	}

	status = cmd_interface_mctp_control_init(&mctp_wrapper->cmd_mctp_control,
			device_mgr, CERBERUS_PROTOCOL_INTEL_PFR_PCI_VID, 0x05);
	if (status != 0) {
		LOG_ERR("mctp control command interface init failed");
		goto error_device_mgr;
	}
#if defined(CONFIG_PFR_PLDM_FW_UPDATE)
	pfr_mctp_enable_pldm_type(&mctp_wrapper->cmd_mctp_control);
#endif

	mctp_wrapper->cmd_cerberus.process_request = cmd_interface_system_process_request;
	mctp_wrapper->cmd_cerberus.process_response = cmd_interface_system_process_response;
	mctp_wrapper->cmd_cerberus.generate_error_packet = cmd_interface_generate_error_packet;

	status = mctp_interface_init(&mctp_wrapper->mctp_interface, &mctp_wrapper->cmd_cerberus,
			&mctp_wrapper->cmd_mctp_control.base, NULL, device_mgr);
	if (status != 0) {
		LOG_ERR("mctp interface init failed");
		goto error_cmd_interface;
	}

	return 0;

error_cmd_interface:
	cmd_interface_mctp_control_deinit(&mctp_wrapper->cmd_mctp_control);
error_device_mgr:
	device_manager_release(device_mgr);

	return status;
}

void mctp_interface_wrapper_deinit(struct mctp_interface_wrapper *mctp_wrapper)
{
	device_manager_release(&mctp_wrapper->device_mgr);
	cmd_interface_mctp_control_deinit(&mctp_wrapper->cmd_mctp_control);
	mctp_interface_deinit(&mctp_wrapper->mctp_interface);
}

#endif // CONFIG_PFR_MCTP
