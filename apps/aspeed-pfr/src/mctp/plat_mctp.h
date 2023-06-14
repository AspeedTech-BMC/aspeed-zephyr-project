/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "mctp_utils.h"

typedef struct _mctp_smbus_port {
	mctp *mctp_inst;
	mctp_medium_conf conf;
} mctp_smbus_port;

typedef struct _mctp_i3c_dev {
	mctp *mctp_inst;
	mctp_i3c_conf i3c_conf;
} mctp_i3c_dev;

/* init the mctp moduel for platform */
void plat_mctp_init(void);
mctp *find_mctp_by_smbus(uint8_t bus);
mctp *find_mctp_by_i3c(uint8_t bus);

