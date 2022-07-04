/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "state_machine.h"
#include "common_smc.h"

#define BMC_RELEASE                             1U
#define PCH_RELEASE                             1U

#define TOTAL_RETRIES                   3

#define PRIMARY_FLASH_REGION    1
#define SECONDARY_FLASH_REGION  2
#define RECOVER_FROM_BACKUP             1
#define RECOVER_FROM_ACTIVE             1
#define NUMBER_OF_DATA_ENTRY    4

#define EVENT_STATE_HANDLED             0

#define UPDATE_CAPSULE          1
#define ACTIVE_PFM              2
#define ASPEED_PFR_FIRMWARE       3

extern struct st_pfr_instance pfr_instance;
extern struct st_manifest_t manifest;
extern int systemState;
extern int gEventCount;
extern int gPublishCount;
// extern uint8_t gBmcFlag;
extern uint8_t gDataCount;
extern uint8_t gProvisionData;
extern volatile struct st_i2cCtx_t i2c_efb;

#pragma pack(1)
typedef struct _EVENT_CONTEXT {
	/* Operation being Performed*/
	unsigned int operation;
	/* Number Of Retries*/
	unsigned char retries;
	/* BMC image or PCH Image*/
	unsigned int image;
	// Active or Backup Region to Verify.
	// 1 - Active
	// 2 - Backup
	// Identifies region to recover
	// 0 - primary->secondary
	// 1 - secondary->primary
	unsigned int flash;
	unsigned int *i2c_data;
} EVENT_CONTEXT;

typedef struct _AO_DATA {
	int type;
	union {
		struct {
			unsigned int ActiveImageVerified : 1;
			unsigned int RecoveryImageVerified : 1;
			unsigned int StagingImageVerified : 1;
			unsigned int InLockdown : 1;
			unsigned int ActiveImageStatus : 1;
			unsigned int RecoveryImageStatus : 1;
			unsigned int RestrictActiveUpdate : 1;
			unsigned int PreviousState : 2;
			unsigned int BootPlatform : 1;
			unsigned int ProcessNewCommand : 1;
			unsigned int processOnce : 1;
		};
		unsigned int flag;
	};
} AO_DATA;

static enum SystemState {
	Initial = 1,
	Verify,
	Recovery,
	Update
} SystemState;

static enum OPERATIONS {
	VERIFY_ACTIVE = 1,
	VERIFY_BACKUP,
	RECOVER_ACTIVE,
	RECOVER_BACKUP_IMAGE,
	UPDATE_BACKUP,
	RELEASE_HOLD,
	I2C_HANDLE
} OPERATIONS;
#pragma pack()

