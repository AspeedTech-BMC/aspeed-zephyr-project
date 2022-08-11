/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#if defined(CONFIG_INTEL_PFR)
#include <stdint.h>
#include "intel_pfr_verification.h"

/*
 * revise provisioned data structure in UFM
 * increase the length of root key hash item to 48 bytes to support both sha256 and sha384
 * change the offset to increase 16 bytes after root key hash items
 *
 */
enum {
	UFM_STATUS,
	ROOT_KEY_HASH                                           = 0x004,
	PCH_ACTIVE_PFM_OFFSET                                   = 0x034,
	PCH_RECOVERY_REGION_OFFSET                              = 0x038,
	PCH_STAGING_REGION_OFFSET                               = 0x03c,
	BMC_ACTIVE_PFM_OFFSET                                   = 0x040,
	BMC_RECOVERY_REGION_OFFSET                              = 0x044,
	BMC_STAGING_REGION_OFFSET                               = 0x048,
	PIT_PASSWORD                                            = 0x04c,
	PIT_PCH_FW_HASH                                         = 0x054,
	PIT_BMC_FW_HASH                                         = 0x074,
	SVN_POLICY_FOR_CPLD_UPDATE                              = 0x094,
	SVN_POLICY_FOR_PCH_FW_UPDATE                            = 0x09c,
	SVN_POLICY_FOR_BMC_FW_UPDATE                            = 0x0a4,
	KEY_CANCELLATION_POLICY_FOR_SIGNING_PCH_PFM             = 0x0ac,
	KEY_CANCELLATION_POLICY_FOR_SIGNING_PCH_UPDATE_CAPSULE  = 0x0bc,
	KEY_CANCELLATION_POLICY_FOR_SIGNING_BMC_PFM             = 0x0cc,
	KEY_CANCELLATION_POLICY_FOR_SIGNING_BMC_UPDATE_CAPSULE  = 0x0dc,
	KEY_CANCELLATION_POLICY_FOR_SIGNING_CPLD_UPDATE_CAPSULE = 0x0ec
};

int verify_root_key_entry(struct pfr_manifest *manifest, PFR_AUTHENTICATION_BLOCK1 *block1_buffer);
#endif
