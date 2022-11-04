/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_PFR_MCTP)
#include "cmd_interface/cmd_channel.h"

int cmd_channel_mctp_init(struct cmd_channel *channel, int id);

#endif // CONFIG_PFR_MCTP

