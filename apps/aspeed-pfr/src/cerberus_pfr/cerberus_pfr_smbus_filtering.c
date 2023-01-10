/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>
#include <device.h>
#include <logging/log.h>
#include <drivers/i2c/pfr/i2c_filter.h>
#include "cerberus_pfr/cerberus_pfr_smbus_filtering.h"

LOG_MODULE_DECLARE(pfr, CONFIG_LOG_DEFAULT_LEVEL);

extern struct SMBUS_FILTER_MANIFEST smbus_filter_manifest[4];

void apply_pfm_smbus_protection(uint8_t smbus_filter)
{
	if (smbus_filter > 3) {
		LOG_ERR("SMBus Filter device does not exist");
		return;
	}

	const struct device *flt_dev = NULL;
	char bus_dev_name[] = "I2C_FILTER_x";
	int status = 0;

	bus_dev_name[11] = smbus_filter + '0';
	flt_dev = device_get_binding(bus_dev_name);

	if (flt_dev) {
		for (uint8_t dev_id = 0; dev_id < 16; ++dev_id) {
			if (smbus_filter_manifest[smbus_filter].device[dev_id].enable) {
				/* Load data into aspeed i2c filter */
				status = ast_i2c_filter_en(flt_dev, true, true,	0, 0);
				LOG_DBG("ast_i2c_filter_en ret=%d", status);

				status = ast_i2c_filter_update(
						flt_dev,
						dev_id,
						smbus_filter_manifest[smbus_filter].device[dev_id].slave_addr >> 1,
						smbus_filter_manifest[smbus_filter].device[dev_id].whitelist_cmd
						);
				LOG_DBG("ast_i2c_filter_update ret=%d", status);

				LOG_INF("SMBus Rule Bus[%d] RuleId[%d] DeviceAddr[%02x]",
						smbus_filter, dev_id,
						smbus_filter_manifest[smbus_filter].device[dev_id].slave_addr);

				LOG_HEXDUMP_INF(smbus_filter_manifest[smbus_filter].device[dev_id].whitelist_cmd,
						sizeof(smbus_filter_manifest[smbus_filter].device[dev_id].whitelist_cmd)
						, "Whitelist");
			}
		}
	} else {
		LOG_ERR("%s device not found", bus_dev_name);
		return;
	}
}
