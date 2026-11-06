/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include <mctp.h>
#include <mctp_ctrl.h>
#if defined(CONFIG_SPDM_RESPONDER)
#include <spdm_rsp.h>
#endif
#if defined(CONFIG_PLDM)
#include <pldm.h>
#endif

#include <mctp_vdm_pci.h>

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
#if defined(CONFIG_PLDM)
	case MCTP_MSG_TYPE_PLDM:
		mctp_pldm_cmd_handler(mctp_p, buf, len, ext_params);
		break;
#endif
#if defined(CONFIG_SPDM_RESPONDER)
	case MCTP_MSG_TYPE_SPDM:
	/* libspdm's MCTP transport decodes both; secured ones carry the session */
	case MCTP_MSG_TYPE_SECURED_SPDM:
		mctp_spdm_cmd_handler(mctp_p, buf, len, ext_params);
		break;
#endif
#if defined(CONFIG_COMPOSITE_EAT)
	case MCTP_MSG_TYPE_VEN_DEF_PCI:
		mctp_vdm_pci_cmd_handler(mctp_p, buf, len, ext_params);
		break;
#endif
	default:
		LOG_WRN("Cannot find message receive function!!");
		return MCTP_ERROR;
	}

	return MCTP_SUCCESS;
} 

int load_mctp_support_types(uint8_t *type_len, uint8_t *types, uint8_t max_types)
{
	static const uint8_t supported[] = {
		MCTP_MSG_TYPE_CTRL,
#if defined(CONFIG_PLDM)
		MCTP_MSG_TYPE_PLDM,
#endif
#if defined(CONFIG_SPDM_RESPONDER)
		MCTP_MSG_TYPE_SPDM,
		MCTP_MSG_TYPE_SECURED_SPDM,
#endif
#if defined(CONFIG_COMPOSITE_EAT)
		MCTP_MSG_TYPE_VEN_DEF_PCI,
#endif
	};

	BUILD_ASSERT(ARRAY_SIZE(supported) <= MCTP_MAX_SUPPORTED_MSG_TYPES,
		     "raise MCTP_MAX_SUPPORTED_MSG_TYPES");

	*type_len = 0;
	if (ARRAY_SIZE(supported) > max_types)
		return -ENOMEM;

	memcpy(types, supported, sizeof(supported));
	*type_len = ARRAY_SIZE(supported);

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

