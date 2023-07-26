/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <stdio.h>
#include "cmd_interface/device_manager.h"

#if !defined(CONFIG_I3C_SLAVE)
// TODO: Remove hardcoded slave address if ENTDAA is supported by driver
#define BMC_I3C_SLAVE_ADDR                  0x08
#define CPU0_I3C_SLAVE_ADDR                 0x0A
#define CPU1_I3C_SLAVE_ADDR                 0x0C

void set_prev_mctp_i3c_state(int state);
int mctp_i3c_detach_slave_dev(void);
int mctp_i3c_attach_slave_dev(uint8_t slave_addr);
void mctp_i3c_stop_discovery_notify(struct device_manager *mgr);
#endif

void init_pfr_mctp(void);

