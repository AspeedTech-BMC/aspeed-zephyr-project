/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_PFR_MCTP)
#include "cmd_interface/device_manager.h"
#include "cmd_interface/cmd_interface.h"
#include "mctp/mctp_base_protocol.h"
#include "mctp/cmd_interface_mctp_control.h"

/**
 * Dependencies for the MCTP wrapper.
 */
struct mctp_interface_wrapper {
	struct cmd_interface cmd_cerberus;			/**< Cerberus protocol command interface instance. */
	struct cmd_interface_mctp_control cmd_mctp_control;	/**< MCTP control protocol command interface instance. */
	struct device_manager device_mgr;			/**< Device manager. */
	struct mctp_interface mctp_interface;			/**< MCTP interface instance */
};

int mctp_interface_wrapper_init(struct mctp_interface_wrapper *mctp_wrapper, uint8_t rot_addr);
void mctp_interface_wrapper_deinit(struct mctp_interface_wrapper *mctp_wrapper);

#endif // CONFIG_PFR_MCTP
