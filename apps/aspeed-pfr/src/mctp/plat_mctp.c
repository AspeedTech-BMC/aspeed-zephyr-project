/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_PFR_MCTP)
#include <zephyr.h>
#include <logging/log.h>
#include "mctp/mctp_interface_wrapper.h"
#include "mctp_utils.h"
#include "plat_mctp.h"
#include "cmd_channel_mctp.h"

LOG_MODULE_REGISTER(plat_mctp, CONFIG_LOG_DEFAULT_LEVEL);

/* i2c dev bus */
#define I2C_BUS_BMC 0x00
#define I2C_BUS_PCH 0x02

/* i2c 7 bit address */
#define I2C_ADDR_ROT_FOR_BMC 0x38
#define I2C_ADDR_ROT_FOR_PCH 0x70

static mctp_smbus_port smbus_port[] = {
	{ .conf.smbus_conf.bus = I2C_BUS_BMC, .conf.smbus_conf.rot_addr = I2C_ADDR_ROT_FOR_BMC },
};

mctp *find_mctp_by_smbus(uint8_t bus)
{
	uint8_t i;

	for (i = 0; i < ARRAY_SIZE(smbus_port); i++) {
		mctp_smbus_port *p = smbus_port + i;

		if (bus == p->conf.smbus_conf.bus)
			return p->mctp_inst;
	}

	return NULL;
}

void plat_mctp_init(void)
{
	LOG_INF("plat_mctp_init");

	/* init the mctp instance */
	for (uint8_t i = 0; i < ARRAY_SIZE(smbus_port); i++) {
		mctp_smbus_port *p = smbus_port + i;

		LOG_DBG("smbus port %d", i);
		LOG_DBG("bus = %x, rot_addr = %x", p->conf.smbus_conf.bus, p->conf.smbus_conf.rot_addr);

		p->mctp_inst = mctp_init();
		if (!p->mctp_inst) {
			LOG_ERR("mctp_init failed!!");
			continue;
		}
		LOG_DBG("jamin mctp instance address =%p", p->mctp_inst);
		// debug
		uint8_t rc;

		mctp_interface_wrapper_init(&p->mctp_inst->mctp_wrapper, p->conf.smbus_conf.rot_addr);
		cmd_channel_mctp_init(&p->mctp_inst->mctp_cmd_channel, p->conf.smbus_conf.bus);

		LOG_DBG("mctp_inst = %p", p->mctp_inst);
		rc = mctp_set_medium_configure(p->mctp_inst, MCTP_MEDIUM_TYPE_SMBUS, p->conf);
		LOG_DBG("mctp_set_medium_configure %s",
			(rc == MCTP_SUCCESS) ? "success" : "failed");

		mctp_start(p->mctp_inst);
	}
}

#endif // CONFIG_PFR_MCTP
