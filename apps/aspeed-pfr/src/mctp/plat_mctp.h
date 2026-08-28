/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "mctp.h"

/*
 * Per-index match clause, compiled in only if that i2cN nodelabel exists on
 * this SoC at all - DT_NODELABEL(i2cN) is not safe to reference otherwise
 * (unlike the DT_NODE_HAS_STATUS()/IS_ENABLED() checks in i2c_util.h, a bare
 * DT_SAME_NODE/DT_BUS on a nonexistent label fails the build, it does not
 * just evaluate false).
 */
#define I2C_BUS_MATCH(node, n) \
	IF_ENABLED(DT_NODE_EXISTS(DT_NODELABEL(i2c##n)), \
		(DT_SAME_NODE(DT_BUS(node), DT_NODELABEL(i2c##n)) ? n :))

#define I2C_BUS_OF(node) ( \
	I2C_BUS_MATCH(node, 0) \
	I2C_BUS_MATCH(node, 1) \
	I2C_BUS_MATCH(node, 2) \
	I2C_BUS_MATCH(node, 3) \
	I2C_BUS_MATCH(node, 4) \
	I2C_BUS_MATCH(node, 5) \
	I2C_BUS_MATCH(node, 6) \
	I2C_BUS_MATCH(node, 7) \
	I2C_BUS_MATCH(node, 8) \
	I2C_BUS_MATCH(node, 9) \
	I2C_BUS_MATCH(node, 10) \
	I2C_BUS_MATCH(node, 11) \
	I2C_BUS_MATCH(node, 12) \
	I2C_BUS_MATCH(node, 13) \
	I2C_BUS_MATCH(node, 14) \
	I2C_BUS_MATCH(node, 15) \
	-1)

#define I2C_BUS_BMC I2C_BUS_OF(DT_ALIAS(bmc_mctp_i2c))
#define I2C_BUS_PCH I2C_BUS_OF(DT_ALIAS(pch_mctp_i2c))

#define I2C_ADDR_ROT_FOR_BMC DT_REG_ADDR(DT_ALIAS(bmc_mctp_i2c))
#define I2C_ADDR_ROT_FOR_PCH DT_REG_ADDR(DT_ALIAS(pch_mctp_i2c))

#define I2C_MBX_PORT_BMC DT_PROP(DT_ALIAS(bmc_mctp_i2c), port)
#define I2C_MBX_PORT_PCH DT_PROP(DT_ALIAS(pch_mctp_i2c), port)

typedef struct _mctp_smbus_port {
	mctp *mctp_inst;
	mctp_medium_conf conf;
} mctp_smbus_port;

/* init the mctp moduel for platform */
void plat_mctp_init(void);
mctp *find_mctp_by_smbus(uint8_t bus);

