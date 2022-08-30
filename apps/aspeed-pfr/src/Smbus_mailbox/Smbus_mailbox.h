/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "include/SmbusMailBoxCom.h"
#include "AspeedStateMachine/common_smc.h"
#include "StateMachineAction/StateMachineActions.h"

extern int systemState;
extern int gEventCount;
extern int gPublishCount;

typedef struct {
	int signal;
	void *context;
} TUPLE;

#pragma pack(1)

// enum HRoT_state { IDLE, I2C, VERIFY, RECOVERY, UPDATE, LOCKDOWN };

typedef char byte;
#define  BIT2     0x00000004
#define ACM_MAXTIMEOUT 50000
#define BMC_MAXTIMEOUT 175000
#define BIOS_MAXTIMEOUT 900000
// BMC I2c Commands
#define  LOGMESSAGE 0x05

#define READ_ONLY 24
#define WRITE_ONLY 6

typedef struct _SMBUS_MAIL_BOX_ {
	byte CpldIdentifier;
	byte CpldReleaseVersion;
	byte CpldRoTSVN;
	byte PlatformState;
	byte Recoverycount;
	byte LastRecoveryReason;
	byte PanicEventCount;
	byte LastPanicReason;
	byte MajorErrorCode;
	byte MinorErrorCode;
	union {
		struct {
			byte CommandBusy : 1;
			byte CommandDone : 1;
			byte CommandError : 1;
			byte UfmStatusReserved : 1;
			byte UfmLocked : 1;
			byte Ufmprovisioned : 1;
			byte PITlevel1enforced : 1;
			byte PITL2CompleteSuccess : 1;
		};
		byte UfmStatusValue;
	};
	byte UfmCommand;
	union {
		struct {
			byte ExecuteCmd : 1;
			byte FlushWriteFIFO : 1;
			byte FlushReadFIFO : 1;
			byte UfmCmdTriggerReserved : 4;
		};
		byte UfmCmdTriggerValue;
	};
	byte UfmWriteFIFO;
	byte UfmReadFIFO;
	byte BmcCheckpoint;
	byte AcmCheckpoint;
	byte BiosCheckpoint;
	union {
		struct {
			byte PchUpdateIntentPchActive : 1;
			byte PchUpdateIntentPchrecovery : 1;
			byte PchUpdateIntentCpldActive : 1;
			byte PchUpdateIntentBmcActive : 1;
			byte PchUpdateIntentBmcRecovery : 1;
			byte PchUpdateIntentCpldRecovery : 1;
			byte PchUpdateIntentUpdateDynamic : 1;
			byte PchUpdateIntentUpdateAtReset : 1;
		};
		byte PchUpdateIntentValue;
	};
	union {
		struct {
			byte BmcUpdateIntentPchActive : 1;
			byte BmcUpdateIntentPchrecovery : 1;
			byte BmcUpdateIntentCpldActive : 1;
			byte BmcUpdateIntentBmcActive : 1;
			byte BmcUpdateIntentBmcRecovery : 1;
			byte BmcUpdateIntentCpldRecovery : 1;
			byte BmcUpdateIntentUpdateDynamic : 1;
			byte BmcUpdateIntentUpdateAtReset : 1;
		};
		byte BmcUpdateIntentValue;
	};
	byte PchPFMActiveSVN;
	byte PchPFMActiveMajorVersion;
	byte PchPFMActiveMinorVersion;
	byte BmcPFMActiveSVN;
	byte BmcPFMActiveMajorVersion;
	byte BmcPFMActiveMinorVersion;
	byte PchPFMRecoverSVN;
	byte PchPFMRecoverMajorVersion;
	byte PchPFMRecoverMinorVersion;
	byte BmcPFMRecoverSVN;
	byte BmcPFMRecoverMajorVersion;
	byte BmcPFMRecoverMinorVersion;
	byte CpldFPGARoTHash[0x40];
	byte Reserved[0x20];
	byte AcmBiosScratchPad[0x40];
	byte BmcScratchPad[0x40];
} SMBUS_MAIL_BOX;

typedef enum _SMBUS_MAILBOX_RF_ADDRESS_READONLY {
	CpldIdentifier = 0x00,
	CpldReleaseVersion = 0x01,
	CpldRotSvn = 0x02,
	PlatformState = 0x03,
	RecoveryCount = 0x04,
	LastRecoveryReason = 0x05,
	PanicEventCount = 0x06,
	LastPanicReason = 0x07,
	MajorErrorCode = 0x08,
	MinorErrorCode = 0x09,
	UfmStatusValue = 0x0a,
	UfmCommand = 0x0b,
	UfmCmdTriggerValue = 0x0c,
	UfmWriteFIFO = 0x0d,
	UfmReadFIFO = 0x0e,
	BmcCheckpoint = 0x0f,
	AcmCheckpoint = 0x10,
	BiosCheckpoint = 0x11,
	PchUpdateIntent = 0x12,
	BmcUpdateIntent = 0x13,
	PchPfmActiveSvn = 0x14,
	PchPfmActiveMajorVersion = 0x15,
	PchPfmActiveMinorVersion = 0x16,
	BmcPfmActiveSvn = 0x17,
	BmcPfmActiveMajorVersion = 0x18,
	BmcPfmActiveMinorVersion = 0x19,
	PchPfmRecoverSvn = 0x1a,
	PchPfmRecoverMajorVersion = 0x1b,
	PchPfmRecoverMinorVersion = 0x1c,
	BmcPfmRecoverSvn = 0x1d,
	BmcPfmRecoverMajorVersion = 0x1e,
	BmcPfmRecoverMinorVersion = 0x1f,
	CpldFPGARoTHash = 0x20, /* 0x20 - 0x5f */
#if defined(CONFIG_SEAMLESS_UPDATE)
	PchSeamlessUpdateIntent = 0x61,
	BmcSeamlessUpdateIntent = 0x62,
#endif
	Reserved                = 0x63,
	AcmBiosScratchPad       = 0x80,
	BmcScratchPad           = 0xc0,
} SMBUS_MAILBOX_RF_ADDRESS;

typedef enum _EXECUTION_CHECKPOINT {
	ExecutionBlockStrat = 0x01,
	NextExeBlockAuthenticationPass,
	NextExeBlockAuthenticationFail,
	ExitingPlatformManufacturerAuthority,
	StartExternalExecutionBlock,
	ReturnedFromExternalExecutionBlock,
	PausingExecutionBlock,
	ResumedExecutionBlock,
	CompletingExecutionBlock,
	EnteredManagementMode,
	LeavingManagementMode,
	ReadToBootOS = 0x80
} EXECUTION_CHECKPOINT;

typedef enum _UPDATE_INTENT {
	PchActiveUpdate                         = 0x01,
	PchRecoveryUpdate,
	PchActiveAndRecoveryUpdate,
	HROTActiveUpdate,
	BmcActiveUpdate                         = 0x08,
	BmcRecoveryUpdate                       = 0x10,
	HROTRecoveryUpdate                      = 0x20,
	DymanicUpdate                           = 0x40,
	UpdateAtReset                           = 0x80,
	PchActiveAndRecoveryUpdateAtReset       = 0x83,
	PchActiveDynamicUpdate                  = 0x41,
	PchActiveAndDynamicUpdateAtReset        = 0xc1,
	HROTActiveAndRecoveryUpdate             = 0x24,
	BmcActiveAndRecoveryUpdate              = 0x18,
	PchActiveAndBmcActiveUpdate             = 0x09,
	PchRecoveryAndBmcRecvoeryUpdate         = 0x12,
	PchFwAndBmcFwUpdate                     = 0x1B,
	PchBmcHROTActiveAndRecoveryUpdate       = 0x3f,
	BmcActiveAndDynamicUpdate               = 0x48,
	ExceptBmcActiveUpdate                   = 0x37,
	ExceptPchActiveUpdate                   = 0x3E,
} UPDATE_INTENT;

#if defined(CONFIG_SEAMLESS_UPDATE)
typedef enum _SEAMLESS_UPDATE_INTENT {
	PchFvSeamlessUpdate                     = 0x01,
	AfmActiveUpdate                         = 0x02,
	AfmRecoveryUpdate                       = 0x04,
	AfmActiveAndRecoveryUpdate              = 0x06,
} SEAMLESS_UPDATE_INTENT;
#endif

typedef struct _PFM_STRUCTURE {
	uint32_t PfmTag;
	uint8_t SVN;
	uint8_t BkcVersion;
	uint8_t MarjorVersion;
	uint8_t MinorVersion;
	uint32_t Reserved;
	uint8_t OemSpecificData[16];
	uint32_t Length;
} PFM_STRUCTURE;

#pragma pack()

unsigned char set_provision_data_in_flash(uint8_t addr, uint8_t *DataBuffer, uint8_t DataSize);
int get_provision_data_in_flash(uint32_t addr, uint8_t *DataBuffer, uint32_t length);
// void ReadFullUFM(uint32_t UfmId,uint32_t UfmLocation,uint8_t *DataBuffer, uint16_t DataSize);
unsigned char erase_provision_data_in_flash(void);
void GetUpdateStatus(uint8_t *DataBuffer, uint8_t DataSize);
void SetUpdateStatus(uint8_t *DataBuffer, uint8_t DataSize);

void ResetMailBox(void);
void InitializeSmbusMailbox(void);
void SetCpldIdentifier(byte Data);
byte GetCpldIdentifier(void);
void SetCpldReleaseVersion(byte Data);
byte GetCpldReleaseVersion(void);
void SetCpldRotSvn(byte Data);
byte GetCpldRotSvn(void);
byte GetPlatformState(void);
void SetPlatformState(byte PlatformStateData);
byte GetRecoveryCount(void);
void IncRecoveryCount(void);
byte GetLastRecoveryReason(void);

int getFailedUpdateAttemptsCount(void);
void LogErrorCodes(uint8_t major_err, uint8_t minor_err);
void LogUpdateFailure(uint8_t minor_err, uint32_t failed_count);
void ClearUpdateFailure(void);
void LogLastPanic(uint8_t panic);
void LogRecovery(uint8_t reason);
void LogWatchdogRecovery(uint8_t recovery_reason, uint8_t panic_reason);

// void SetLastRecoveryReason(LAST_RECOVERY_REASON_VALUE LastRecoveryReasonValue);
void SetLastRecoveryReason(byte LastRecoveryReasonValue);

byte GetPanicEventCount(void);
void IncPanicEventCount(void);
byte GetLastPanicReason(void);
// void SetLastPanicReason(LAST_PANIC_REASON_VALUE LastPanicReasonValue);
void SetLastPanicReason(byte LastPanicReasonValue);
byte GetMajorErrorCode(void);
// void SetMajorErrorCode(MAJOR_ERROR_CODE_VALUE MajorErrorCodeValue);
void SetMajorErrorCode(byte MajorErrorCodeValue);
byte GetMinorErrorCode(void);
// void SetMinorErrorCode(MINOR_ERROR_CODE_VALUE MinorErrorCodeValue);
void SetMinorErrorCode(byte MinorErrorCodeValue);
bool IsUfmStatusCommandBusy(void);
bool IsUfmStatusCommandDone(void);
bool IsUfmStatusCommandError(void);
bool IsUfmStatusLocked(void);
bool IsUfmStatusUfmProvisioned(void);
bool IsUfmStatusPitLevel1Enforced(void);
bool IsUfmStatusPITL2CompleteSuccess(void);
byte GetUfmStatusValue(void);
void SetUfmStatusValue(uint8_t UfmStatusBitMask);
void ClearUfmStatusValue(uint8_t UfmStatusBitMask);
int CheckUfmStatus(uint32_t UfmStatus, uint32_t UfmStatusBitMask);
void SetUfmCmdTriggerValue(byte);
byte get_provision_command(void);
void set_provision_command(byte UfmCommandValue);
void set_provision_commandTrigger(byte UfmCommandTrigger);
byte GetBmcCheckPoint(void);
void SetBmcCheckPoint(byte BmcCheckpoint);
byte GetBiosCheckPoint(void);
void SetBiosCheckPoint(byte BiosCheckpoint);
bool IsPchUpdateIntentPCHActive(void);
bool IsPchUpdateIntentPchRecovery(void);
bool IsPchUpdateIntentCpldActive(void);
bool IsPchUpdateIntentCpldRecovery(void);
bool IsPchUpdateIntentBmcActive(void);
bool IsPchUpdateIntentBmcRecovery(void);
bool IsPchUpdateIntentUpdateDynamic(void);
bool IsPchUpdateIntentUpdateAtReset(void);
byte GetPchUpdateIntent(void);
void SetPchUpdateIntent(byte PchUpdateIntent);
bool IsBmcUpdateIntentPchActive(void);
bool IsBmcUpdateIntentPchRecovery(void);
bool IsBmcUpdateIntentCpldActive(void);
bool IsBmcUpdateIntentCpldRecovery(void);
bool IsBmcUpdateIntentBmcActive(void);
bool IsBmcUpdateIntentBmcRecovery(void);
bool IsBmcUpdateIntentUpdateDynamic(void);
bool IsBmcUpdateIntentUpdateAtReset(void);
byte GetBmcUpdateIntent(void);
void SetBmcUpdateIntent(byte BmcUpdateIntent);
byte GetPchPfmActiveSvn(void);
void SetPchPfmActiveSvn(byte ActiveSVN);
byte GetPchPfmActiveMajorVersion(void);
void SetPchPfmActiveMajorVersion(byte ActiveMajorVersion);
byte GetPchPfmActiveMinorVersion(void);
void SetPchPfmActiveMinorVersion(byte ActiveMinorVersion);
byte GetBmcPfmActiveSvn(void);
void SetBmcPfmActiveSvn(byte ActiveSVN);
byte GetBmcPfmActiveMajorVersion(void);
void SetBmcPfmActiveMajorVersion(byte ActiveMajorVersion);
byte GetBmcPfmActiveMinorVersion(void);
void SetBmcPfmActiveMinorVersion(byte ActiveMinorVersion);
byte GetPchPfmRecoverSvn(void);
void SetPchPfmRecoverSvn(byte RecoverSVN);
byte GetPchPfmRecoverMajorVersion(void);
void SetPchPfmRecoverMajorVersion(byte RecoverMajorVersion);
byte GetPchPfmRecoverMinorVersion(void);
void SetPchPfmRecoverMinorVersion(byte RecoverMinorVersion);
byte GetBmcPfmRecoverSvn(void);
void SetBmcPfmRecoverSvn(byte RecoverSVN);
byte GetBmcPfmRecoverMajorVersion(void);
void SetBmcPfmRecoverMajorVersion(byte RecoverMajorVersion);
byte GetBmcPfmRecoverMinorVersion(void);
void SetBmcPfmRecoverMinorVersion(byte RecoverMinorVersion);
byte *GetCpldFpgaRotHash(void);
void SetCpldFpgaRotHash(byte *HashData);
byte *GetAcmBiosScratchPad(void);
void SetAcmBiosScratchPad(byte *AcmBiosScratchPad);
byte *GetBmcScratchPad(void);
void SetBmcScratchPad(byte *BmcScratchPad);
void HandleSmbusMailBoxWrite(unsigned char MailboxAddress, unsigned char ValueToWrite, int ImageType);
void HandleSmbusMailBoxRead(int MailboxOffset, int ImageType);
void process_provision_command(void);
void UpdateBiosCheckpoint(byte Data);
void UpdateBmcCheckpoint(byte Data);
void UpdateIntentHandle(byte Data, uint32_t Source);
bool WatchDogTimer(int ImageType);
uint8_t PchBmcCommands(unsigned char *CipherText, uint8_t ReadFlag);
void get_image_svn(uint8_t image_id, uint32_t address, uint8_t *SVN, uint8_t *MajorVersion, uint8_t *MinorVersion);
void initializeFPLEDs(void);
unsigned char erase_provision_flash(void);

#define UFM_STATUS_LOCK_BIT_MASK                      0b1
#define UFM_STATUS_PROVISIONED_ROOT_KEY_HASH_BIT_MASK 0b10
#define UFM_STATUS_PROVISIONED_PCH_OFFSETS_BIT_MASK   0b100
#define UFM_STATUS_PROVISIONED_BMC_OFFSETS_BIT_MASK   0b1000
#define UFM_STATUS_PROVISIONED_PIT_ID_BIT_MASK        0b10000
#define UFM_STATUS_PIT_L1_ENABLE_BIT_MASK             0b100000
#define UFM_STATUS_PIT_L2_ENABLE_BIT_MASK             0b1000000
#define UFM_STATUS_PIT_HASH_STORED_BIT_MASK           0b10000000
#define UFM_STATUS_PIT_L2_PASSED_BIT_MASK             0b100000000

extern uint8_t gBiosBootDone;
extern uint8_t gBmcBootDone;

