/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include "i2c/i2c_filter_wrapper.h"
#include <stdbool.h>
#include <string.h>
// for testing only
#include <shell/shell.h>
#include <device.h>
#include "drivers/i2c.h"
#include <stdlib.h>

/**
 * @brief Initialize specific device of I2C filter
 *
 * @param i2c_filter_interface I2C filter interface to use
 *
 * @return 0 if the I2C filter failed to initialize or an error code.
 */
static int i2c_filter_wrapper_init(struct i2c_filter_interface *filter)
{
	int ret;

	ret = i2c_filter_middleware_init(filter->filter.device_id);

	return ret;
}

/**
 * @brief Enable / disable specific device of I2C filter
 *
 * @param i2c_filter_interface I2C filter interface to use
 * @param en enable I2C filter
 *
 * @return 0 if the I2C filter failed to enable or an error code.
 */
static int i2c_filter_wrapper_en(struct i2c_filter_interface *filter, bool enable)
{
	int ret;

	ret = i2c_filter_middleware_en(filter->filter.device_id, enable);

	return ret;
}

/**
 * @brief Setup whitelist for specific device of I2C filter with provided offset of slave device.
 *                      Index can using on stores every single offset of slave device with each single index.
 *
 * @param i2c_filter_interface I2C filter interface to use
 * @param index Index to stores register address or offset of slave device
 *
 * @return 0 if the I2C filter failed to setup or an error code.
 */
static int i2c_filter_wrapper_set(struct i2c_filter_interface *filter, uint8_t index)
{
	int ret;

	ret = i2c_filter_middleware_set_whitelist(filter->filter.device_id, index,
						  filter->filter.slave_addr, filter->filter.whitelist_elements);

	return ret;
}

/**
 * @brief Retrieves a I2C filter interface provided functions.
 *
 * @param i2c_filter_interface I2C filter interface to use
 *
 * @return 0 if the I2C filter failed to initialization or an error code.
 */
int i2c_filter_wrapper_initialization(struct i2c_filter_interface *filter)
{
	if (filter == NULL) {
		return -1;
	}

	memset(filter, 0, sizeof(filter));

	filter->init_filter = i2c_filter_wrapper_init;
	filter->enable_filter = i2c_filter_wrapper_en;
	filter->set_filter = i2c_filter_wrapper_set;

	return 0;
}

/**
 * testing I2C filter wrapper functions
 */
#ifdef CONFIG_SHELL

LOG_MODULE_REGISTER(i2c_filter_wrapper_shell, CONFIG_LOG_DEFAULT_LEVEL);

/** shell input :
 *
 * i2c_filter_wrapper whitelist_test I2C_FILTER_x I2C_x (slave_addr) (whitelist index) (.... whitelist)
 *
 * ex ) $ i2c_filter_wrapper whitelist_test I2C_FILTER_0 I2C_8 51 0
 *              = All data is allowed pass through filter from I2C_8 to 0x51 address of slave device
 *
 * ex ) $ i2c_filter_wrapper whitelist_test I2C_FILTER_0 I2C_8 51 0 EC 11
 *              = Only offset 0xEC and 0x11 are allowed pass through filter from I2C_8 to 0x51 address of slave device
 *
 */
static int i2c_filter_wrapper_test(const struct shell *shell,
				   size_t argc, char **argv)
{
	struct i2c_filter_interface i2c_filter_tst;
	const struct device *master_dev;
	uint8_t slave_addr, offset;
	uint8_t whitelist_idx, whitelist_dat;
	char *master_name, *filter_name;
	uint8_t buf[6];
	bool whitelist_allow;
	uint32_t whitelist_elements[8];

	filter_name = argv[1];
	master_name = argv[2];
	slave_addr = strtol(argv[3], NULL, 16);
	whitelist_idx = strtol(argv[4], NULL, 16);

	if (argc > 5) {
		// Initializes all offset being block by I2C filter
		memset(whitelist_elements, 0, sizeof(whitelist_elements));

		while (argc-- > 5) {
			// retrieves whitelist from input
			whitelist_dat = strtol(argv[argc], NULL, 16);
			// setup whitelist/allow-list in corresponding bit position.
			// ex : whitelist value as 0x10 mapping to bit[16]
			whitelist_elements[whitelist_dat / 32] |=
				BIT(whitelist_dat % 32);
		}
	} else {
		// allow all offset being pass through I2C filter
		memset(whitelist_elements, 0xFF, sizeof(whitelist_elements));
	}

	shell_print(shell, "whitelist table\n");
	shell_hexdump(shell, (const uint8_t *)whitelist_elements, sizeof(whitelist_elements));

	if (i2c_filter_wrapper_initialization(&i2c_filter_tst)) {
		shell_error(shell,
			    "i2c filter wrapper test failed : Failed on %s\n",
			    "i2c_filter_wrapper_initialization");
		return -1;
	}

	//	convert I2C filter device number from string to number,
	//	wrapper parameters only keeps number of filter device rather than string
	i2c_filter_tst.filter.device_id =
		filter_name[sizeof(I2C_FILTER_MIDDLEWARE_PREFIX) - sizeof("")] - '0';

	if (i2c_filter_tst.init_filter(&i2c_filter_tst)) {
		shell_error(shell,
			    "i2c filter wrapper test failed : Failed to %s\n",
			    "i2c_filter_tst.init_filter");
		return -1;
	}

	i2c_filter_tst.filter.slave_addr = slave_addr;
	i2c_filter_tst.filter.whitelist_elements = whitelist_elements;

	if (i2c_filter_tst.set_filter(&i2c_filter_tst, whitelist_idx)) {
		shell_error(shell,
			    "i2c filter wrapper test failed : Failed to %s\n",
			    "i2c_filter_tst.set_filter");
		return -1;
	}

	master_dev = device_get_binding(master_name);

	if (!master_dev) {
		shell_error(shell,
			    "%s : master I2C device is not found\n",
			    "i2c filter wrapper test failed");
		return -1;
	}

	offset = 0;

	do {
		buf[0] = offset;

		whitelist_allow =
			(whitelist_elements[offset / 32] & BIT(offset % 32)) ? 1 : 0;

		if (i2c_write(master_dev, buf, sizeof(buf), i2c_filter_tst.filter.slave_addr)) {
			if (whitelist_allow) {
				shell_error(shell,
					    "%s : wl = [0x%02X]\n master failed write to filter\n",
					    "i2c filter wrapper test failed", offset);
				return -1;
			}
		} else {
			if (!whitelist_allow) {
				shell_error(shell,
					    "%s : wl = [0x%02X]\n master success write to device, should blocked by filter\n",
					    "i2c filter wrapper test failed", offset);
				return -1;
			}
		}

		k_msleep(10);   // delay a write time for I2C EEPROM operation
	} while (++offset != 0);

	shell_info(shell, "i2c filter wrapper test : PASS!\n");

	return 0;
}

static void device_name_get(size_t idx, struct shell_static_entry *entry);

SHELL_DYNAMIC_CMD_CREATE(dsub_device_name, device_name_get);

static void device_name_get(size_t idx, struct shell_static_entry *entry)
{
	const struct device *dev = shell_device_lookup(idx, I2C_FILTER_MIDDLEWARE_PREFIX);

	entry->syntax = (dev != NULL) ? dev->name : NULL;
	entry->handler = NULL;
	entry->help = NULL;
	entry->subcmd = NULL;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_i2c_filter_wrapper_cmds,
			       SHELL_CMD_ARG(whitelist_test, &dsub_device_name,
					     "setup whitelist to testing features of I2C filter",
					     i2c_filter_wrapper_test, 5, 16),

			       SHELL_SUBCMD_SET_END              /* Array terminated. */
			       );

SHELL_CMD_REGISTER(i2c_filter_wrapper, &sub_i2c_filter_wrapper_cmds, "I2C filter wrapper commands", NULL);

#endif // CONFIG_SHELL
