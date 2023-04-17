/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

void init_pfr_mctp(void);
#if !defined(CONFIG_I3C_SLAVE)
int mctp_i3c_dettach_slave_dev(void);
int mctp_i3c_attach_slave_dev(void);
#endif

