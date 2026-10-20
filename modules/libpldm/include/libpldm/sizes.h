/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * Stands in for the <libpldm/sizes.h> that libpldm's meson build generates
 * from sizeof() of its internal structures; take them from the same headers.
 */

#pragma once

#include "control-internal.h"
#include "firmware_device/fd-internal.h"

/* sizeof(struct pldm_fd) */
#define PLDM_SIZEOF_PLDM_FD sizeof(struct pldm_fd)

/* sizeof(struct pldm_control) */
#define PLDM_SIZEOF_PLDM_CONTROL sizeof(struct pldm_control)
