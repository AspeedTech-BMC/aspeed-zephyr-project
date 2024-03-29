/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include "pfr/pfr_common.h"
#include "cerberus_pfr_definitions.h"

#define PROVISIONING_IMAGE_TYPE			0x02
#define PROVISION_ROOT_KEY_FLAG			0x01
#define PROVISION_OTP_KEY_FLAG			0x0f
#define PROVISIONING_ROOT_KEY_HASH_TYPE		HASH_TYPE_SHA256
#define PROVISIONING_ROOT_KEY_HASH_LENGTH	SHA256_DIGEST_LENGTH

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
	PIT_BMC_FW_HASH                                         = 0x094,
	SVN_POLICY_FOR_CPLD_UPDATE                              = 0x0d4,
	SVN_POLICY_FOR_PCH_FW_UPDATE                            = 0x0dc,
	SVN_POLICY_FOR_BMC_FW_UPDATE                            = 0x0e4,
	KEY_CANCELLATION_POLICY_FOR_SIGNING_PCH_PFM             = 0x0ec,
	KEY_CANCELLATION_POLICY_FOR_SIGNING_PCH_UPDATE_CAPSULE  = 0x0fc,
	KEY_CANCELLATION_POLICY_FOR_SIGNING_BMC_PFM             = 0x10c,
	KEY_CANCELLATION_POLICY_FOR_SIGNING_BMC_UPDATE_CAPSULE  = 0x11c,
	KEY_CANCELLATION_POLICY_FOR_SIGNING_CPLD_UPDATE_CAPSULE = 0x12c
};

enum CERBERUS_PROVISION_STRUCT {
	CERBERUS_PROVISION_IMAGE_LENGTH                         = 0x000,
	CERBERUS_IMAGE_TYPE                                     = 0x002,
	CERBERUS_MAGIC_NUM                                      = 0x004,
	CERBERUS_MANIFEST_LENGTH                                = 0x008,
	CERBERUS_MANIFEST_FLAG                                  = 0x00a,
	CERBERUS_PROVISION_RESERVED                             = 0x00e,
	CERBERUS_BMC_ACTIVE_OFFSET                              = 0x010,
	CERBERUS_BMC_ACTIVE_SIZE                                = 0x014,
	CERBERUS_BMC_RECOVERY_OFFSET                            = 0x018,
	CERBERUS_BMC_RECOVERY_SIZE                              = 0x01c,
	CERBERUS_BMC_STAGE_OFFSET                               = 0x020,
	CERBERUS_BMC_STAGE_SIZE                                 = 0x024,
	CERBERUS_PCH_ACTIVE_OFFSET                              = 0x028,
	CERBERUS_PCH_ACTIVE_SIZE                                = 0x02c,
	CERBERUS_PCH_RECOVERY_OFFSET                            = 0x030,
	CERBERUS_PCH_RECOVERY_SIZE                              = 0x034,
	CERBERUS_PCH_STAGE_OFFSET                               = 0x038,
	CERBERUS_PCH_STAGE_SIZE                                 = 0x03c,
	CERBERUS_ROOT_KEY                                       = 0x040,
	CERBERUS_KEY_MANIFEST                                   = 0x800
};

struct PROVISIONING_IMAGE_HEADER {
	uint16_t image_length;
	uint16_t image_type;
	uint32_t magic_num;
	uint16_t manifest_length;
	uint8_t provisioning_flag[4];
	uint8_t reserved[2];
};

int cerberus_provisioning_root_key_action(struct pfr_manifest *manifest);

