/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>

#define PRIMARY_FLASH_REGION    1
#define SECONDARY_FLASH_REGION  2

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
	unsigned int flag;
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

enum OPERATIONS {
	VERIFY_ACTIVE = 1,
	VERIFY_BACKUP,
	RECOVER_ACTIVE,
	RECOVER_BACKUP_IMAGE,
	UPDATE_BACKUP,
#if defined(CONFIG_SEAMLESS_UPDATE)
	SEAMLESS_UPDATE_OP,
#endif
	RELEASE_HOLD,
	I2C_HANDLE
};
#pragma pack()

void AspeedPFR_EnableTimer(int type);
void AspeedPFR_DisableTimer(int type);
