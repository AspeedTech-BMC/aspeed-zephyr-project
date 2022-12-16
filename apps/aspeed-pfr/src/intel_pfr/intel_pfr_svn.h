/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include "pfr/pfr_common.h"

int set_ufm_svn(uint32_t offset, uint8_t svn);
uint8_t get_ufm_svn(uint32_t offset);
int svn_policy_verify(uint32_t offset, uint32_t svn);
int read_statging_area_pfm_svn(struct pfr_manifest *manifest, uint8_t *svn_version);

