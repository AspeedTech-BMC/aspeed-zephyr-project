/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>
#include <logging/log.h>
#include "i2c/hal_i2c.h"
#include "i3c/hal_i3c.h"
#include "plat_mctp.h"

LOG_MODULE_REGISTER(mctp, CONFIG_LOG_DEFAULT_LEVEL);

void init_pfr_mctp(void)
{
	util_init_I2C();
#if defined(CONFIG_PFR_MCTP_I3C) && defined(CONFIG_I3C_ASPEED)
	util_init_i3c();
#endif
	plat_mctp_init();
}

