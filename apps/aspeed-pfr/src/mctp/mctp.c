/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>
#include <logging/log.h>
#include "i2c/hal_i2c.h"
#include "plat_mctp.h"

LOG_MODULE_REGISTER(mctp, CONFIG_LOG_DEFAULT_LEVEL);

void init_pfr_mctp(void)
{
	util_init_I2C();
	plat_mctp_init();
}

