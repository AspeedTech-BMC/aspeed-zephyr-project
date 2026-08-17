/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdbool.h>

#include "mctp.h"

struct cmd_packet;

bool pldm_transport_process_packet(mctp *mctp_inst, struct cmd_packet *packet);
void pldm_transport_reset(mctp *mctp_inst);
void pldm_transport_deinit(mctp *mctp_inst);
