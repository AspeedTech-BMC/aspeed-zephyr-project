/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>

#include <mctp.h>
#include <mctp_ctrl.h>

LOG_MODULE_REGISTER(mctp_init);

static mctp_port mctp_bus_port[] = {
#if defined(CONFIG_IPM)
	{
		.medium_type = MCTP_MEDIUM_TYPE_IPC,
		.conf.ipc_conf.id = 0, 
		.conf.ipc_conf.rsz = 0,
	}
#endif
};

static uint8_t get_mctp_route_info(uint8_t dest_endpoint, void **mctp_inst,
				   mctp_ext_params *ext_params)
{
	return MCTP_ERROR;
}

static uint8_t mctp_msg_recv(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_params ext_params)
{
	if (!mctp_p || !buf || !len)
		return MCTP_ERROR;

	/* first byte is message type and ic */
	uint8_t msg_type = (buf[0] & MCTP_MSG_TYPE_MASK) >> MCTP_MSG_TYPE_SHIFT;
	uint8_t ic = (buf[0] & MCTP_IC_MASK) >> MCTP_IC_SHIFT;
	(void)ic;

	LOG_HEXDUMP_DBG(buf, len, "mctp_msg_recv");
	switch (msg_type) {
	case MCTP_MSG_TYPE_CTRL:
		mctp_ctrl_cmd_handler(mctp_p, buf, len, ext_params);
		break;
	default:
		LOG_WRN("Cannot find message receive function!!");
		return MCTP_ERROR;
	}

	return MCTP_SUCCESS;
} 

int load_mctp_support_types(uint8_t *type_len, uint8_t *types)
{
	*type_len = 1;
	types[0] = MCTP_MSG_TYPE_CTRL;

	return 0;
}

int mctp_init_app()
{
	LOG_INF("Start MCTP INIT");

	for (size_t i=0; i< ARRAY_SIZE(mctp_bus_port); i++) {

		LOG_INF("MCTP bus %d addr 0x%x", mctp_bus_port[i].conf.ipc_conf.id,
			mctp_bus_port[i].conf.ipc_conf.rsz);
		
		mctp_bus_port[i].mctp_inst = mctp_init();
		if (!mctp_bus_port[i].mctp_inst) {
			LOG_ERR("MCTP init inst failed");
			continue;
		}

		uint8_t ret;
		ret = mctp_set_medium_configure(
				mctp_bus_port[i].mctp_inst,
				mctp_bus_port[i].medium_type,
				mctp_bus_port[i].conf);
		LOG_INF("Set MCTP medium configure ret: %d", ret);

		ret = mctp_reg_endpoint_resolve_func(mctp_bus_port[i].mctp_inst, get_mctp_route_info);
		LOG_INF("Register endpoint resolve function ret: %d", ret);

		ret = mctp_reg_msg_rx_func(mctp_bus_port[i].mctp_inst, mctp_msg_recv);
		LOG_INF("Register message receive function ret: %d", ret);

		ret = mctp_start(mctp_bus_port[i].mctp_inst);
		LOG_INF("Start MCTP bus ret: %d", ret);

	}
	return 0;
}

