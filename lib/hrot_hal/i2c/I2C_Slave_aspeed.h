/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ZEPHYR_INCLUDE_I2C_SLAVE_DEVICE_API_MIDLEYER_H_
#define ZEPHYR_INCLUDE_I2C_SLAVE_DEVICE_API_MIDLEYER_H_
#include <zephyr/types.h>
#include <stddef.h>
#include <device.h>
/*typedef struct _SMBUS_MAIL_BOX {
	uint8_t CpldIdentifier;		//00h
	uint8_t CpldReleaseVersion;	//01h
	uint8_t CpldRoTSVN;		//02h
	uint8_t PlatformState;		//03h
	uint8_t Recoverycount;		//04h
	uint8_t LastRecoveryReason;	//05h
	uint8_t PanicEventCount;	//06h
	uint8_t LastPanicReason;	//07h
	uint8_t MajorErrorCode;		//08h
	uint8_t MinorErrorCode;		//09h
	union {
		struct {
			uint8_t CommandBusy :1;
			uint8_t CommandDone :1;
			uint8_t CommandError :1;
			uint8_t UfmStatusReserved :1;
			uint8_t UfmLocked :1;
			uint8_t Ufmprovisioned :1;
			uint8_t PITlevel1enforced :1;
			uint8_t PITL2CompleteSuccess :1;
		};
		uint8_t UfmStatusValue; //0Ah
	};
	uint8_t UfmCommand; //0Bh
	union {
		struct {
			uint8_t ExecuteCmd :1;
			uint8_t FlushWriteFIFO :1;
			uint8_t FlushReadFIFO :1;
			uint8_t UfmCmdTriggerReserved :4;
		};
		uint8_t UfmCmdTriggerValue;		//0Ch
	};
	uint8_t UfmWriteFIFO;				//0Dh
	uint8_t UfmReadFIFO;				//0Eh
	uint8_t BmcCheckpoint;				//0Fh
	uint8_t AcmCheckpoint;				//10h
	uint8_t BiosCheckpoint;				//11h
	union {
		struct {
			uint8_t PchUpdateIntentPchActive : 1;
			uint8_t PchUpdateIntentPchrecovery : 1;
			uint8_t PchUpdateIntentCpldActive : 1;
			uint8_t PchUpdateIntentBmcActive : 1;
			uint8_t PchUpdateIntentBmcRecovery : 1;
			uint8_t PchUpdateIntentCpldRecovery : 1;
			uint8_t PchUpdateIntentUpdateDynamic : 1;
			uint8_t PchUpdateIntentUpdateAtReset : 1;
		};
		uint8_t PchUpdateIntentValue;	//12h
	};
	union {
		struct {
			uint8_t BmcUpdateIntentPchActive : 1;
			uint8_t BmcUpdateIntentPchrecovery : 1;
			uint8_t BmcUpdateIntentCpldActive : 1;
			uint8_t BmcUpdateIntentBmcActive : 1;
			uint8_t BmcUpdateIntentBmcRecovery : 1;
			uint8_t BmcUpdateIntentCpldRecovery : 1;
			uint8_t BmcUpdateIntentUpdateDynamic : 1;
			uint8_t BmcUpdateIntentUpdateAtReset : 1;
		};
		uint8_t BmcUpdateIntentValue;	//13h
	};
	uint8_t PchPFMActiveSVN;			//14h
	uint8_t PchPFMActiveMajorVersion;	//15h
	uint8_t PchPFMActiveMinorVersion;	//16h
	uint8_t BmcPFMActiveSVN;			//17h
	uint8_t BmcPFMActiveMajorVersion;	//18h
	uint8_t BmcPFMActiveMinorVersion;	//19h
	uint8_t PchPFMRecoverSVN;			//1Ah
	uint8_t PchPFMRecoverMajorVersion;	//1Bh
	uint8_t PchPFMRecoverMinorVersion;	//1Ch
	uint8_t BmcPFMRecoverSVN;			//1Dh
	uint8_t BmcPFMRecoverMajorVersion;	//1Eh
	uint8_t BmcPFMRecoverMinorVersion;	//1Fh
	uint8_t CpldFPGARoTHash[0x40];		//20h to 5Fh
	uint8_t BmcCheckpoint_Pfr30;		//60h
	union {
		struct {
			uint8_t PchUpdateIntent2SeamlessUpdateIntent : 1;
		};
		uint8_t PchUpdateIntent2Value;	//61h
	};
	union {
		struct {
			uint8_t BmcUpdateIntent2SeamlessUpdateIntent : 1;
		};
		uint8_t BmcUpdateIntent2Value;	//62h
	};
	uint8_t Reserved[0x1D];				//63h to 7Fh
	uint8_t AcmBiosScratchPad[0x40];	//80h to BFh
	uint8_t BmcScratchPad[0x40];		//C0h to FFh
}SMBUS_MAIL_BOX;

typedef enum _SMBUS_MAILBOX_RF_ADDRESS_READONLY{
    CpldIdentifier,
    CpldReleaseVersion,
    CpldRoTSVN,
    PlatformState,
    Recoverycount,
    LastRecoveryReason,
    PanicEventCount,
    LastPanicReason,
    MajorErrorCode,
    MinorErrorCode,
    UfmStatusValue,
    UfmCommand,
    UfmCmdTriggerValue,
    UfmWriteFIFO,
    UfmReadFIFO,
    BmcCheckpoint,
    AcmCheckpoint,
    BiosCheckpoint,
    PchUpdateIntentValue,
    BmcUpdateIntentValue,
    PchPFMActiveSVN,
    PchPFMActiveMajorVersion,
    PchPFMActiveMinorVersion,
    BmcPFMActiveSVN,
    BmcPFMActiveMajorVersion,
    BmcPFMActiveMinorVersion,
    PchPFMRecoverSVN,
    PchPFMRecoverMajorVersion,
    PchPFMRecoverMinorVersion,
    BmcPFMRecoverSVN,
    BmcPFMRecoverMajorVersion,
    BmcPFMRecoverMinorVersion,
    CpldFPGARoTHash,
    AMIReadLogRsv = 0x7F,
    AcmBiosScratchPad = 0x80,
    BmcScratchPad = 0xc0,
} SMBUS_MAILBOX_RF_ADDRESS;*/

typedef struct _I2C_Slave_Process {
	uint8_t InProcess;
	uint8_t operation;
	uint8_t DataBuf[2];
} I2C_Slave_Process;

enum {
	SLAVE_IDLE,
	MASTER_CMD_READ,
	MASTER_DATA_READ_SLAVE_DATA_SEND,
};

#define SLAVE_BUF_INDEX0 0x00
#define SLAVE_BUF_INDEX1 0x01

#define SlaveDataReceiveComplete 0x02
#define I2CInProcess_Flag 0x01

int ast_i2c_slave_dev_init(const struct device *dev, uint8_t slave_addr);
//void PchBmcProcessCommands(unsigned char *CipherText);

#define SLAVE_BUF_DMA_MODE 0
#define SLAVE_BUF_BUFF_MODE 1
#define SLAVE_BUF_BYTE_MODE 2
#define SLAVE_BUF_B_size 0x80
#endif
