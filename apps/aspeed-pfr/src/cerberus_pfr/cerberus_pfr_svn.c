/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>
#include <logging/log.h>
#include <stdint.h>
#include "pfr/pfr_common.h"
#include "AspeedStateMachine/common_smc.h"

uint8_t get_ufm_svn(uint32_t offset)
{
	return 0;
}

int pfr_active_recovery_svn_validation(struct pfr_manifest *manifest)
{
	return Success;
}

