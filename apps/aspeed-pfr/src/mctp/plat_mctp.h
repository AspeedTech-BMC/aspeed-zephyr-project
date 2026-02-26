/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "mctp.h"

/* i2c dev bus */
#define I2C_BUS_BMC 0x00

#if defined(CONFIG_BOARD_AST2700_DCSCM)
#define I2C_BUS_PCH 0x05
#else
#define I2C_BUS_PCH 0x02
#endif

typedef struct _mctp_smbus_port {
	mctp *mctp_inst;
	mctp_medium_conf conf;
} mctp_smbus_port;

/* init the mctp moduel for platform */
void plat_mctp_init(void);
mctp *find_mctp_by_smbus(uint8_t bus);

