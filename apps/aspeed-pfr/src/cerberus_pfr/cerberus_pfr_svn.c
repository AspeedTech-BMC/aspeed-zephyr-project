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

int does_staged_fw_image_match_active_fw_image(struct pfr_manifest *manifest)
{
	return Success;
}

