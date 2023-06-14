/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>
#include <device.h>
#include <logging/log.h>
#include <drivers/i2c/pfr/swmbx.h>
#include "Smbus_mailbox/Smbus_mailbox.h"
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

extern const struct device *gSwMbxDev;

static mctp_smbus_port smbus_port[] = {
	{
	 .conf.smbus_conf.bus = I2C_BUS_BMC,
	 .conf.smbus_conf.rot_addr = I2C_ADDR_ROT_FOR_BMC,
	 .conf.smbus_conf.mbx_port = 0
	},
	{
	 .conf.smbus_conf.bus = I2C_BUS_PCH,
	 .conf.smbus_conf.rot_addr = I2C_ADDR_ROT_FOR_PCH,
	 .conf.smbus_conf.mbx_port = 1
	},
};

#if defined(CONFIG_PFR_MCTP_I3C) && defined(CONFIG_I3C_ASPEED)
#define I3C_BUS_BMC          0x02
#if defined(CONFIG_I3C_SLAVE)
#define I3C_DEV_ADDR         0x09
#else
#define I3C_DEV_ADDR         0x08
#endif

mctp_i3c_dev i3c_dev = {
	.i3c_conf.bus = I3C_BUS_BMC,
	.i3c_conf.addr = I3C_DEV_ADDR,
};
#endif

K_SEM_DEFINE(mctp_fifo_state_sem, 0, 1);

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

#if defined(CONFIG_PFR_MCTP_I3C) && defined(CONFIG_I3C_ASPEED)
mctp *find_mctp_by_i3c(uint8_t bus)
{
	if (bus == 2)
		return i3c_dev.mctp_inst;
	else
		return NULL;
}
#endif

void plat_mctp_init(void)
{
	LOG_INF("plat_mctp_init");
	uint8_t i, rc;

	if (gSwMbxDev == NULL) {
		LOG_ERR("without SWMBX device");
		return;
	}

	/* update mailbox fifo */
	swmbx_update_fifo(gSwMbxDev,
		&mctp_fifo_state_sem,
		2,
		MCTPWriteFIFO,
		0xF0,
		SWMBX_FIFO_NOTIFY_STOP,
		true);
	swmbx_flush_fifo(gSwMbxDev, MCTPWriteFIFO);

	/* init the mctp instance */
	for (i = 0; i < ARRAY_SIZE(smbus_port); i++) {
		mctp_smbus_port *p = smbus_port + i;

		LOG_DBG("smbus port %d", i);
		LOG_DBG("bus = %x, rot_addr = %x", p->conf.smbus_conf.bus, p->conf.smbus_conf.rot_addr);

		p->mctp_inst = mctp_init();
		if (!p->mctp_inst) {
			LOG_ERR("mctp_init failed!!");
			continue;
		}

		/* Register mailbox notification semaphore */
		k_sem_init(&p->mctp_inst->rx_fifo_in_data_sem, 0, 1);
		swmbx_update_notify(gSwMbxDev,
			p->conf.smbus_conf.mbx_port,
			&p->mctp_inst->rx_fifo_in_data_sem,
			MCTPWriteFIFO,
			true);
		p->mctp_inst->sw_mbx_dev = gSwMbxDev;

		/* Register mctp command channel and interface */
		rc = cmd_channel_mctp_init(&p->mctp_inst->mctp_cmd_channel, p->conf.smbus_conf.bus);
		if (rc != MCTP_SUCCESS) {
			LOG_ERR("mctp cmd channel init failed");
			continue;
		}

		rc = mctp_interface_wrapper_init(&p->mctp_inst->mctp_wrapper, p->conf.smbus_conf.rot_addr);
		if (rc != MCTP_SUCCESS) {
			LOG_ERR("mctp interface wrapper init failed!!");
			continue;
		}

		LOG_DBG("mctp_inst = %p", p->mctp_inst);
		rc = mctp_set_medium_configure(p->mctp_inst, MCTP_MEDIUM_TYPE_SMBUS, p->conf);
		LOG_DBG("mctp_set_medium_configure %s",
			(rc == MCTP_SUCCESS) ? "success" : "failed");

		mctp_start(p->mctp_inst);
	}

#if defined(CONFIG_PFR_MCTP_I3C) && defined(CONFIG_I3C_ASPEED)
	mctp_i3c_dev *i3c_dev_p;
	mctp *mctp_instance;
	int mctp_channel_id;

	i3c_dev_p = &i3c_dev;
	i3c_dev_p->mctp_inst = mctp_init();
	mctp_instance = i3c_dev_p->mctp_inst;
	if (!mctp_instance) {
		LOG_ERR("Failed to allocate mctp instance for i3c");
		return;
	}
	mctp_set_medium_configure(mctp_instance, MCTP_MEDIUM_TYPE_I3C,
			mctp_instance->medium_conf);
	mctp_instance->medium_conf.i3c_conf.bus = i3c_dev_p->i3c_conf.bus;
	mctp_instance->medium_conf.i3c_conf.addr = i3c_dev_p->i3c_conf.addr;
	mctp_channel_id = CMD_CHANNEL_I3C_BASE | mctp_instance->medium_conf.i3c_conf.bus;
	rc = cmd_channel_mctp_init(&mctp_instance->mctp_cmd_channel,
			mctp_channel_id);
	if (rc != MCTP_SUCCESS) {
		LOG_ERR("i3c mctp cmd channel init failed");
		return;
	}

#if defined(CONFIG_I3C_SLAVE)
	rc = mctp_interface_wrapper_init(&mctp_instance->mctp_wrapper,
			mctp_instance->medium_conf.i3c_conf.addr);
#else
	rc = mctp_i3c_wrapper_init(&mctp_instance->mctp_wrapper,
			mctp_instance->medium_conf.i3c_conf.addr);
#endif
	if (rc != MCTP_SUCCESS) {
		LOG_ERR("i3c mctp interface wrapper init failed!!");
		return;
	}

	mctp_interface_set_channel_id(&mctp_instance->mctp_wrapper.mctp_interface,
			mctp_channel_id);
	printk("mctp_intf = %p\n", &mctp_instance->mctp_wrapper.mctp_interface);

	LOG_INF("MCTP over I3C start");
	mctp_start(mctp_instance);
#endif
}

