/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>

#include "mctp.h"

struct mctp_i3c_role_ops {
	int (*resolve_dest_eid)(mctp *mctp_instance, uint8_t *dest_eid);
};

/* CMake selects exactly one controller or target role implementation. */
extern const struct mctp_i3c_role_ops mctp_i3c_role;
