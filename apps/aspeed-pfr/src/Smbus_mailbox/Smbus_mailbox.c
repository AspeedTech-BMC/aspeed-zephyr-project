/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <logging/log.h>
#include "Smbus_mailbox.h"
#include "common/common.h"
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_provision.h"
#include <drivers/i2c.h>
#include <drivers/i2c/pfr/swmbx.h>

LOG_MODULE_REGISTER(mailbox, CONFIG_LOG_DEFAULT_LEVEL);

#if SMBUS_MAILBOX_DEBUG
#define DEBUG_PRINTF LOG_INF
#else
#define DEBUG_PRINTF(...)
#endif

#define READ_ONLY_RF_COUNT  20
#define READ_WRITE_RF_COUNT 06

#define PRIMARY_FLASH_REGION    1
#define SECONDARY_FLASH_REGION  2

struct device *gSwMbxDev = NULL;
uint8_t gReadOnlyRfAddress[READ_ONLY_RF_COUNT] = { 0x1, 0x2, 0x3, 0x04, 0x05, 0x06, 0x07, 0x0A, 0x14, 0x15, 0x16, 0x17,
						   0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
uint8_t gReadAndWriteRfAddress[READ_WRITE_RF_COUNT] = { 0x08, 0x09, 0x0B, 0x0C, 0x0D, 0x0E };
extern struct st_pfr_instance pfr_instance;
EVENT_CONTEXT DataContext;

uint8_t gUfmFifoData[64];
uint8_t gReadFifoData[64];
uint8_t gRootKeyHash[SHA384_DIGEST_LENGTH];
uint8_t gPchOffsets[12];
uint8_t gBmcOffsets[12];
uint8_t gUfmFifoLength;
uint8_t gbmcactivesvn;
uint8_t gbmcactiveMajorVersion;
uint8_t gbmcActiveMinorVersion;
uint8_t gAcmBootDone = FALSE;
uint8_t gBiosBootDone = FALSE;
uint8_t gBmcBootDone = FALSE;
uint8_t gObbBootDone = FALSE;
uint8_t gWDTUpdate = 0;
uint8_t gProvisinDoneFlag = FALSE;
// uint8_t MailboxBuffer[256]={0};
extern bool gBootCheckpointReceived;
extern uint32_t gMaxTimeout;
extern int gBMCWatchDogTimer;
extern int gPCHWatchDogTimer;
uint8_t gProvisionCount = 0;
uint8_t gFifoData = 0;
uint8_t gBmcFlag;
uint8_t gDataCount;
uint8_t gProvisionData = 0;
CPLD_STATUS cpld_update_status;

EVENT_CONTEXT UpdateEventData;
AO_DATA UpdateActiveObject;


void ResetMailBox(void)
{
	memset(&gSmbusMailboxData, 0, sizeof(gSmbusMailboxData));
	SetUfmStatusValue(COMMAND_DONE);   // reset ufm status
	SetUfmCmdTriggerValue(0x00);
}
/**
 * Function to Erase th UFM
 * @Param  NULL
 * @retval NULL
 **/
unsigned char erase_provision_flash(void)
{
	int status;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.device_id[0] = ROT_INTERNAL_INTEL_STATE;
	status = spi_flash->spi.base.sector_erase(&spi_flash->spi, 0);
	return status;
}
/**
 * Function to Initialize Smbus Mailbox with default value
 * @Param  NULL
 * @retval NULL
 **/
void get_provision_data_in_flash(uint32_t addr, uint8_t *DataBuffer, uint32_t length)
{
	uint8_t status;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.device_id[0] = ROT_INTERNAL_INTEL_STATE; // Internal UFM SPI
	status = spi_flash->spi.base.read(&spi_flash->spi, addr, DataBuffer, length);

}

unsigned char set_provision_data_in_flash(uint8_t addr, uint8_t *DataBuffer, uint8_t DataSize)
{
	uint8_t status;
	uint8_t buffer[256];
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.device_id[0] = ROT_INTERNAL_INTEL_STATE;

	// Read Intel State
	status = spi_flash->spi.base.read(&spi_flash->spi, 0, buffer, ARRAY_SIZE(buffer));

	if (status == Success) {
		status = erase_provision_flash();

		if (status == Success) {
			for (int i = addr; i < DataSize + addr; i++)
				buffer[i] = DataBuffer[i - addr];

			memcpy(buffer + addr, DataBuffer, DataSize);
			status = spi_flash->spi.base.write(&spi_flash->spi, 0, buffer, ARRAY_SIZE(buffer));
		}
	}

	spi_flash->spi.device_id[0] = ROT_INTERNAL_INTEL_STATE;
	status = spi_flash->spi.base.read(&spi_flash->spi, 0, buffer, ARRAY_SIZE(buffer));

	return status;
}
void get_image_svn(uint8_t image_id, uint32_t address, uint8_t *SVN, uint8_t *MajorVersion, uint8_t *MinorVersion)
{
	uint8_t status;
	PFM_STRUCTURE Buffer;

	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.device_id[0] = image_id; // Internal UFM SPI
	status = spi_flash->spi.base.read(&spi_flash->spi, address, &Buffer, sizeof(PFM_STRUCTURE));

	*SVN = Buffer.SVN;
	*MajorVersion = Buffer.MarjorVersion;
	*MinorVersion = Buffer.MinorVersion;
}

#define SWMBX_NOTIFYEE_STACK_SIZE 1024
struct k_thread swmbx_notifyee_thread;
K_THREAD_STACK_DEFINE(swmbx_notifyee_stack, SWMBX_NOTIFYEE_STACK_SIZE);
K_SEM_DEFINE(ufm_write_fifo_state_sem, 0, 1);
K_SEM_DEFINE(ufm_write_fifo_data_sem, 0, 1);
K_SEM_DEFINE(ufm_read_fifo_state_sem, 0, 1);
K_SEM_DEFINE(ufm_provision_trigger_sem, 0, 1);
K_SEM_DEFINE(bmc_update_intent_sem, 0, 1);
K_SEM_DEFINE(pch_update_intent_sem, 0, 1);
K_SEM_DEFINE(bmc_checkpoint_sem, 0, 1);
K_SEM_DEFINE(acm_checkpoint_sem, 0, 1);
K_SEM_DEFINE(bios_checkpoint_sem, 0, 1);

void swmbx_notifyee_main(void *a, void *b, void *c)
{
	struct k_poll_event events[8];
	AO_DATA aodata[8];
	EVENT_CONTEXT evt_ctx[8];
	uint8_t buffer[8][2] = { { 0 } };

	k_poll_event_init(&events[0], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &ufm_write_fifo_data_sem);
	k_poll_event_init(&events[1], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &ufm_read_fifo_state_sem);
	k_poll_event_init(&events[2], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &ufm_provision_trigger_sem);
	k_poll_event_init(&events[3], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &bmc_update_intent_sem);
	k_poll_event_init(&events[4], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &pch_update_intent_sem);
	k_poll_event_init(&events[5], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &bmc_checkpoint_sem);
	k_poll_event_init(&events[6], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &acm_checkpoint_sem);
	k_poll_event_init(&events[7], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &bios_checkpoint_sem);

	int ret;

	while (1) {
		ret = k_poll(events, 8, K_FOREVER);
		if (ret < 0) {
			DEBUG_PRINTF("%s: k_poll error ret=%d", ret);
			continue;
		}

		if (events[0].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* UFM Write FIFO from BMC/PCH */
			k_sem_take(events[0].sem, K_NO_WAIT);
			// TODO: race condition
			do {
				uint8_t c;

				ret = swmbx_read(gSwMbxDev, true, UfmWriteFIFO, &c);
				if (!ret)
					gUfmFifoData[gFifoData++] = c;
			} while (!ret);
		} else if (events[1].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* UFM Read FIFO empty prepare next data */
			k_sem_take(events[1].sem, K_NO_WAIT);
		} else if (events[2].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* UFM Provision Trigger */
			k_sem_take(events[2].sem, K_NO_WAIT);
			aodata[2].ProcessNewCommand = 1;
			aodata[2].type = I2C_EVENT;
			evt_ctx[2].operation = I2C_HANDLE;
			evt_ctx[2].i2c_data = buffer[2];
			buffer[2][0] = UfmCmdTriggerValue;
			swmbx_get_msg(0, UfmCmdTriggerValue, &buffer[2][1]);

			post_smc_action(I2C, &aodata[2], &evt_ctx[2]);
		} else if (events[3].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* BMC Update Intent */
			k_sem_take(events[3].sem, K_NO_WAIT);
			aodata[3].ProcessNewCommand = 1;
			aodata[3].type = I2C_EVENT;
			evt_ctx[3].operation = I2C_HANDLE;
			evt_ctx[3].i2c_data = buffer[3];
			buffer[3][0] = BmcUpdateIntent;
			swmbx_get_msg(0, BmcUpdateIntent, &buffer[3][1]);

			post_smc_action(I2C, &aodata[3], &evt_ctx[3]);
		} else if (events[4].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* PCH Update Intent */
			k_sem_take(events[4].sem, K_NO_WAIT);
		} else if (events[5].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* BMC Checkpoint */
			k_sem_take(events[5].sem, K_NO_WAIT);
			aodata[5].ProcessNewCommand = 1;
			aodata[5].type = I2C_EVENT;
			evt_ctx[5].operation = I2C_HANDLE;
			evt_ctx[5].i2c_data = buffer[5];
			buffer[5][0] = BmcCheckpoint;
			swmbx_get_msg(0, BmcCheckpoint, &buffer[5][1]);

			post_smc_action(I2C, &aodata[5], &evt_ctx[5]);
		} else if (events[6].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* ACM Checkpoint */
			k_sem_take(events[6].sem, K_NO_WAIT);
		} else if (events[7].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* BIOS Checkpoint */
			k_sem_take(events[7].sem, K_NO_WAIT);
		}

		for (size_t i = 0; i < 8; ++i)
			events[i].state = K_POLL_STATE_NOT_READY;
	}
}

void InitializeSoftwareMailbox(void)
{
	/* Top level mailbox device driver */
	const struct device *swmbx_dev = NULL;

	swmbx_dev = device_get_binding("SWMBX");
	if (swmbx_dev == NULL) {
		DEBUG_PRINTF("%s: fail to bind %s", "SWMBX");
		return;
	}
	gSwMbxDev = swmbx_dev;

	/* Enable mailbox read/write notifiaction and FIFO */
	swmbx_enable_behavior(swmbx_dev, SWMBX_NOTIFY | SWMBX_FIFO, 1);

	/* Register mailbox notification semphore */
	swmbx_update_fifo(swmbx_dev, &ufm_write_fifo_state_sem, 0, UfmWriteFIFO, 0x40, SWMBX_FIFO_NOTIFY_STOP, true);
	swmbx_update_fifo(swmbx_dev, &ufm_read_fifo_state_sem, 1, UfmReadFIFO, 0x40, SWMBX_FIFO_NOTIFY_STOP, true);

	/* swmbx_update_notify(dev, port, sem, addr, enable) */
	swmbx_update_notify(swmbx_dev, 0x0, &ufm_write_fifo_data_sem, UfmWriteFIFO, true);
	swmbx_update_notify(swmbx_dev, 0x0, &ufm_provision_trigger_sem, UfmCmdTriggerValue, true);
	swmbx_update_notify(swmbx_dev, 0x0, &bmc_update_intent_sem, BmcUpdateIntent, true);
	swmbx_update_notify(swmbx_dev, 0x0, &pch_update_intent_sem, PchPfmActiveSvn, true);
	swmbx_update_notify(swmbx_dev, 0x0, &bmc_checkpoint_sem, BmcCheckpoint, true);
	swmbx_update_notify(swmbx_dev, 0x0, &acm_checkpoint_sem, AcmCheckpoint, true);
	swmbx_update_notify(swmbx_dev, 0x0, &bios_checkpoint_sem, BiosCheckpoint, true);

	/* Register slave device to bus device */
	const struct device *dev = NULL;

	dev = device_get_binding("SWMBX_SLAVE_BMC");
	if (dev)
		i2c_slave_driver_register(dev);

	/* TODO: CPU0 */
	dev = device_get_binding("SWMBX_SLAVE_CPU");
	if (dev)
		i2c_slave_driver_register(dev);

	k_tid_t swmbx_tid = k_thread_create(
		&swmbx_notifyee_thread,
		swmbx_notifyee_stack,
		SWMBX_NOTIFYEE_STACK_SIZE,
		swmbx_notifyee_main,
		NULL, NULL, NULL,
		5, 0, K_NO_WAIT);
	k_thread_name_set(swmbx_tid, "Software Mailbox Handler");

}

void InitializeSmbusMailbox(void)
{
	uint32_t UfmStatus;

	InitializeSoftwareMailbox();
	ResetMailBox();

	SetCpldIdentifier(0xDE);
	SetCpldReleaseVersion(CPLD_RELEASE_VERSION);
	uint8_t CurrentSvn = 0;

	// get root key hash
	get_provision_data_in_flash(ROOT_KEY_HASH, gRootKeyHash, SHA384_DIGEST_LENGTH);
	get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, gPchOffsets, sizeof(gPchOffsets));
	get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, gBmcOffsets, sizeof(gBmcOffsets));
	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));

	if (CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_ROOT_KEY_HASH_BIT_MASK |
			   UFM_STATUS_PROVISIONED_PCH_OFFSETS_BIT_MASK |
			   UFM_STATUS_PROVISIONED_BMC_OFFSETS_BIT_MASK)) {
		SetUfmStatusValue(UFM_PROVISIONED);
	}

	if (CheckUfmStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK))
		SetUfmStatusValue(UFM_LOCKED);

	if (CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_PCH_OFFSETS_BIT_MASK)) {
		uint8_t PCHActiveMajorVersion, PCHActiveMinorVersion;
		uint8_t PCHActiveSVN;
		uint32_t pch_pfm_address;

		memcpy(&pch_pfm_address, gPchOffsets, 4);
		pch_pfm_address += 1024;
		get_image_svn(PCH_SPI, pch_pfm_address, &PCHActiveSVN, &PCHActiveMajorVersion, &PCHActiveMinorVersion);
		SetPchPfmActiveSvn(PCHActiveSVN);
		SetPchPfmActiveMajorVersion(PCHActiveMajorVersion);
		SetPchPfmActiveMinorVersion(PCHActiveMinorVersion);

		uint8_t PCHRecoveryMajorVersion, PCHRecoveryMinorVersion;
		uint8_t PCHRecoverySVN;
		uint32_t pch_rec_address;

		memcpy(&pch_rec_address, gPchOffsets + 4, 4);
		pch_rec_address += 2048;
		get_image_svn(PCH_SPI, pch_rec_address, &PCHRecoverySVN, &PCHRecoveryMajorVersion, &PCHRecoveryMinorVersion);
		SetPchPfmRecoverSvn(PCHRecoverySVN);
		SetPchPfmRecoverMajorVersion(PCHRecoveryMajorVersion);
		SetPchPfmRecoverMinorVersion(PCHRecoveryMinorVersion);
	}
	// f1
	if (CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_BMC_OFFSETS_BIT_MASK)) {
		uint8_t BMCActiveMajorVersion, BMCActiveMinorVersion;
		uint8_t BMCActiveSVN;
		uint32_t bmc_pfm_address;

		memcpy(&bmc_pfm_address, gBmcOffsets, 4);
		bmc_pfm_address += 1024;
		get_image_svn(BMC_SPI, bmc_pfm_address, &BMCActiveSVN, &BMCActiveMajorVersion, &BMCActiveMinorVersion);
		SetBmcPfmActiveSvn(BMCActiveSVN);
		SetBmcPfmActiveMajorVersion(BMCActiveMajorVersion);
		SetBmcPfmActiveMinorVersion(BMCActiveMinorVersion);

		uint8_t BMCRecoveryMajorVersion, BMCRecoveryMinorVersion;
		uint8_t BMCRecoverySVN;
		uint32_t bmc_rec_address;

		memcpy(&bmc_rec_address, gBmcOffsets + 4, 4);
		bmc_rec_address += 2048;
		get_image_svn(BMC_SPI, bmc_rec_address, &BMCRecoverySVN, &BMCRecoveryMajorVersion, &BMCRecoveryMinorVersion);
		SetBmcPfmRecoverSvn(BMCRecoverySVN);
		SetBmcPfmRecoverMajorVersion(BMCRecoveryMajorVersion);
		SetBmcPfmRecoverMinorVersion(BMCRecoveryMinorVersion);
	}

	uint8_t current_svn;

	current_svn = get_ufm_svn(NULL, SVN_POLICY_FOR_CPLD_UPDATE);
	// CurrentSvn = Get_Ufm_SVN_Number(SVN_POLICY_FOR_CPLD_UPDATE);
	SetCpldRotSvn(current_svn);
}

#define MBX_REG_SETTER(REG) \
	void Set##REG(byte Data) \
	{ \
		swmbx_write(gSwMbxDev, false, REG, &Data); \
	} 

#define MBX_REG_INC(REG) \
	void Inc##REG() \
	{ \
		byte data; \
		swmbx_read(gSwMbxDev, false, REG, &data); \
		++data; \
		swmbx_write(gSwMbxDev, false, REG, &data); \
	} 

#define MBX_REG_GETTER(REG) \
	byte Get##REG(void) \
	{ \
		byte data; \
		swmbx_read(gSwMbxDev, false, REG, &data); \
		return data; \
	}

#define MBX_REG_SETTER_GETTER(REG) \
	MBX_REG_SETTER(REG) \
	MBX_REG_GETTER(REG)

#define MBX_REG_INC_GETTER(REG) \
	MBX_REG_INC(REG) \
	MBX_REG_GETTER(REG)

MBX_REG_SETTER_GETTER(CpldIdentifier);
MBX_REG_SETTER_GETTER(CpldReleaseVersion);
MBX_REG_SETTER_GETTER(CpldRotSvn);
MBX_REG_SETTER_GETTER(PlatformState);
MBX_REG_INC_GETTER(RecoveryCount);
MBX_REG_SETTER_GETTER(LastRecoveryReason);
MBX_REG_INC_GETTER(PanicEventCount);
MBX_REG_SETTER_GETTER(LastPanicReason);
MBX_REG_SETTER_GETTER(MajorErrorCode);
MBX_REG_SETTER_GETTER(MinorErrorCode);
MBX_REG_GETTER(UfmStatusValue);
MBX_REG_GETTER(UfmCommand);
MBX_REG_SETTER_GETTER(UfmCmdTriggerValue);
MBX_REG_SETTER_GETTER(BmcCheckpoint);
MBX_REG_SETTER_GETTER(AcmCheckpoint);
MBX_REG_SETTER_GETTER(BiosCheckpoint);
MBX_REG_SETTER_GETTER(BmcUpdateIntent);
MBX_REG_SETTER_GETTER(PchPfmActiveSvn);
MBX_REG_SETTER_GETTER(PchPfmActiveMajorVersion);
MBX_REG_SETTER_GETTER(PchPfmActiveMinorVersion);
MBX_REG_SETTER_GETTER(BmcPfmActiveSvn);
MBX_REG_SETTER_GETTER(BmcPfmActiveMajorVersion);
MBX_REG_SETTER_GETTER(BmcPfmActiveMinorVersion);
MBX_REG_SETTER_GETTER(PchPfmRecoverSvn);
MBX_REG_SETTER_GETTER(PchPfmRecoverMajorVersion);
MBX_REG_SETTER_GETTER(PchPfmRecoverMinorVersion);
MBX_REG_SETTER_GETTER(BmcPfmRecoverSvn);
MBX_REG_SETTER_GETTER(BmcPfmRecoverMajorVersion);
MBX_REG_SETTER_GETTER(BmcPfmRecoverMinorVersion);

// UFM Status
void SetUfmStatusValue(uint8_t UfmStatusBitMask)
{
	uint8_t status = GetUfmStatusValue();

	status |= UfmStatusBitMask;
	swmbx_write(gSwMbxDev, false, UfmStatusValue, &status);
}

void ClearUfmStatusValue(uint8_t UfmStatusBitMask)
{
	uint8_t status = GetUfmStatusValue();

	status &= ~UfmStatusBitMask;
	swmbx_write(gSwMbxDev, false, UfmStatusValue, &status);
}

void SetUfmFlashStatus(uint32_t UfmStatus, uint32_t UfmStatusBitMask)
{
	UfmStatus &= ~UfmStatusBitMask;
	set_provision_data_in_flash(UFM_STATUS, &UfmStatus, 4);
}

int CheckUfmStatus(uint32_t UfmStatus, uint32_t UfmStatusBitMask)
{
	return ((~UfmStatus & UfmStatusBitMask) == UfmStatusBitMask);
}

bool IsUfmStatusCommandBusy(void)
{
	return gSmbusMailboxData.CommandBusy ? true : false;
}

bool IsUfmStatusCommandDone(void)
{
	return gSmbusMailboxData.CommandDone ? true : false;
}

bool IsUfmStatusCommandError(void)
{
	return gSmbusMailboxData.CommandError ? true : false;
}

bool IsUfmStatusLocked(void)
{
	return gSmbusMailboxData.UfmLocked ? true : false;
}

bool IsUfmStatusUfmProvisioned(void)
{
	return gSmbusMailboxData.Ufmprovisioned ? true : false;
}

bool IsUfmStatusPitLevel1Enforced(void)
{
	return gSmbusMailboxData.PITlevel1enforced ? true : false;
}

bool IsUfmStatusPITL2CompleteSuccess(void)
{
	return gSmbusMailboxData.PITL2CompleteSuccess ? true : false;
}

// PCH UpdateIntent
bool IsPchUpdateIntentPCHActive(void)
{
	return gSmbusMailboxData.PchUpdateIntentPchActive ? true : false;
}

bool IsPchUpdateIntentPchRecovery(void)
{
	return gSmbusMailboxData.PchUpdateIntentPchrecovery ? true : false;
}

bool IsPchUpdateIntentCpldActive(void)
{
	return gSmbusMailboxData.PchUpdateIntentCpldActive ? true : false;
}

bool IsPchUpdateIntentCpldRecovery(void)
{
	return gSmbusMailboxData.PchUpdateIntentCpldRecovery ? true : false;
}

bool IsPchUpdateIntentBmcActive(void)
{
	return gSmbusMailboxData.PchUpdateIntentBmcActive ? true : false;
}

bool IsPchUpdateIntentBmcRecovery(void)
{
	return gSmbusMailboxData.PchUpdateIntentBmcRecovery ? true : false;
}

bool IsPchUpdateIntentUpdateDynamic(void)
{
	return gSmbusMailboxData.PchUpdateIntentUpdateDynamic ? true : false;
}

bool IsPchUpdateIntentUpdateAtReset(void)
{
	return gSmbusMailboxData.PchUpdateIntentUpdateAtReset ? true : false;
}

byte GetPchUpdateIntent(void)
{
	return gSmbusMailboxData.PchUpdateIntentValue;
}

void SetPchUpdateIntent(byte PchUpdateIntent)
{
	gSmbusMailboxData.PchUpdateIntentValue = PchUpdateIntent;
	// UpdateMailboxRegisterFile(PchUpdateIntentValue, (uint8_t)gSmbusMailboxData.PchUpdateIntentValue);

}

// BMC UpdateIntent
bool IsBmcUpdateIntentPchActive(void)
{
	return gSmbusMailboxData.BmcUpdateIntentPchActive ? true : false;
}

bool IsBmcUpdateIntentPchRecovery(void)
{
	return gSmbusMailboxData.BmcUpdateIntentPchrecovery ? true : false;
}

bool IsBmcUpdateIntentCpldActive(void)
{
	return gSmbusMailboxData.BmcUpdateIntentCpldActive ? true : false;
}

bool IsBmcUpdateIntentCpldRecovery(void)
{
	return gSmbusMailboxData.BmcUpdateIntentCpldRecovery ? true : false;
}

bool IsBmcUpdateIntentBmcActive(void)
{
	return gSmbusMailboxData.BmcUpdateIntentBmcActive ? true : false;
}

bool IsBmcUpdateIntentBmcRecovery(void)
{
	return gSmbusMailboxData.BmcUpdateIntentBmcRecovery ? true : false;
}

bool IsBmcUpdateIntentUpdateDynamic(void)
{
	return gSmbusMailboxData.BmcUpdateIntentUpdateDynamic ? true : false;
}

bool IsBmcUpdateIntentUpdateAtReset(void)
{
	return gSmbusMailboxData.BmcUpdateIntentUpdateAtReset ? true : false;
}


byte *GetCpldFpgaRotHash(void)
{
	uint8_t HashData[SHA256_DIGEST_LENGTH] = { 0 };

	memcpy(HashData, gSmbusMailboxData.CpldFPGARoTHash, SHA256_DIGEST_LENGTH);
	// add obb read code for bmc
	return gSmbusMailboxData.CpldFPGARoTHash;
}

void SetCpldFpgaRotHash(byte *HashData)
{
	memcpy(gSmbusMailboxData.CpldFPGARoTHash, HashData, 64);
	// UpdateMailboxRegisterFile(CpldFPGARoTHash, (uint8_t)gSmbusMailboxData.CpldFPGARoTHash);
}

byte *GetAcmBiosScratchPad(void)
{
	return gSmbusMailboxData.AcmBiosScratchPad;
}

void SetAcmBiosScratchPad(byte *AcmBiosScratchPad)
{
	memcpy(gSmbusMailboxData.AcmBiosScratchPad, AcmBiosScratchPad, 0x40);
}

unsigned char ProvisionRootKeyHash(void)
{
	uint8_t Status;
	uint32_t UfmStatus;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));
	if (!CheckUfmStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK) && !CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_ROOT_KEY_HASH_BIT_MASK)) {
		Status = set_provision_data_in_flash(ROOT_KEY_HASH, gRootKeyHash, SHA384_DIGEST_LENGTH);
		if (Status == Success) {
			DEBUG_PRINTF("Root key provisioned");
			SetUfmFlashStatus(UfmStatus, UFM_STATUS_PROVISIONED_ROOT_KEY_HASH_BIT_MASK);
			return Success;
		}

		DEBUG_PRINTF("Root key provision failed...");
		erase_provision_flash();
		return Failure;
	}

	DEBUG_PRINTF("%s, Provisioned or UFM Locked", __func__);
	return UnSupported;
}

unsigned char ProvisionPchOffsets(void)
{
	uint8_t Status;
	uint32_t UfmStatus;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));
	if (!CheckUfmStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK) && !CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_PCH_OFFSETS_BIT_MASK)) {
		Status = set_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, gPchOffsets, sizeof(gPchOffsets));
		if (Status == Success) {
			DEBUG_PRINTF("PCH offsets provisioned");
			SetUfmFlashStatus(UfmStatus, UFM_STATUS_PROVISIONED_PCH_OFFSETS_BIT_MASK);
			return Success;
		}

		DEBUG_PRINTF("PCH offsets provision failed...");
		erase_provision_flash();
		return Failure;
	}

	DEBUG_PRINTF("%s, Provisioned or UFM Locked", __func__);
	return UnSupported;
}

unsigned char ProvisionBmcOffsets(void)
{
	uint8_t Status;
	uint32_t UfmStatus;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));

	if (!CheckUfmStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK) && !CheckUfmStatus(UfmStatus, UFM_STATUS_PROVISIONED_BMC_OFFSETS_BIT_MASK)) {
		Status = set_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, gBmcOffsets, sizeof(gBmcOffsets));
		if (Status == Success) {
			SetUfmFlashStatus(UfmStatus, UFM_STATUS_PROVISIONED_BMC_OFFSETS_BIT_MASK);
			DEBUG_PRINTF("BMC offsets provisioned");
			return Success;
		}

		DEBUG_PRINTF("BMC offsets provision failed...");
		erase_provision_flash();
		return Failure;
	}

	DEBUG_PRINTF("%s, Provisioned or UFM Locked", __func__);
	return UnSupported;
}

void lock_provision_flash(void)
{
	uint32_t UfmStatus;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));
	SetUfmFlashStatus(UfmStatus, UFM_STATUS_LOCK_BIT_MASK);
}

void ReadRootKey(void)
{
	get_provision_data_in_flash(ROOT_KEY_HASH, gRootKeyHash, SHA384_DIGEST_LENGTH);
	memcpy(gReadFifoData, gRootKeyHash, SHA384_DIGEST_LENGTH);
	for (size_t i = 0; i < SHA384_DIGEST_LENGTH; ++i)
		swmbx_write(gSwMbxDev, true, UfmReadFIFO, gRootKeyHash + i);
}

void ReadPchOfsets(void)
{
	get_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, gPchOffsets, sizeof(gPchOffsets));
	memcpy(gReadFifoData, gPchOffsets, sizeof(gPchOffsets));
	for (size_t i = 0; i < sizeof(gPchOffsets); ++i)
		swmbx_write(gSwMbxDev, true, UfmReadFIFO, gPchOffsets + i);
}

void ReadBmcOffets(void)
{
	get_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, gBmcOffsets, sizeof(gBmcOffsets));
	memcpy(gReadFifoData, gBmcOffsets, sizeof(gBmcOffsets));
	for (size_t i = 0; i < sizeof(gBmcOffsets); ++i)
		swmbx_write(gSwMbxDev, true, UfmReadFIFO, gBmcOffsets + i);
}

/**
 * Function to process th UFM command operations
 * @Param  NULL
 * @retval NULL
 **/
void process_provision_command(void)
{
	uint32_t UfmFlashStatus;
	byte UfmCommandData;
	byte Status = 0;

	UfmCommandData = GetUfmCommand();
	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmFlashStatus, sizeof(UfmFlashStatus));

	if (CheckUfmStatus(UfmFlashStatus, UFM_STATUS_LOCK_BIT_MASK)) {
		if ((UfmCommandData < READ_ROOT_KEY) || (UfmCommandData > READ_BMC_OFFSET)) {
			// Ufm locked
			DEBUG_PRINTF("UFM Locked and Dropped Write Command: 0x%x", UfmCommandData);
			return;
		}
	}

	switch (UfmCommandData) {
	case ERASE_CURRENT:
		Status = erase_provision_flash();
		if (Status == Success) {
			gProvisionCount = 0;
			ClearUfmStatusValue(UFM_CLEAR_ON_ERASE_COMMAND);
		} else {
			SetUfmStatusValue(COMMAND_ERROR);
		}
		break;
	case PROVISION_ROOT_KEY:
		memcpy(gRootKeyHash, gUfmFifoData, SHA384_DIGEST_LENGTH);
		gProvisionCount |= 1 << 0;
		gProvisionData = 1;
		break;
	case PROVISION_PIT_KEY:
		// Update password to provsioned UFM
		DEBUG_PRINTF("PIT IS NOT SUPPORTED");
		break;
	case PROVISION_PCH_OFFSET:
		memcpy(gPchOffsets, gUfmFifoData, sizeof(gPchOffsets));
		gProvisionCount |= 1 << 1;
		gProvisionData = 1;
		break;
	case PROVISION_BMC_OFFSET:
		memcpy(gBmcOffsets, gUfmFifoData, sizeof(gBmcOffsets));
		gProvisionCount |= 1 << 2;
		gProvisionData = 1;
		break;
	case LOCK_UFM:
		// lock ufm
		lock_provision_flash();
		SetUfmStatusValue(UFM_LOCKED);
		break;
	case READ_ROOT_KEY:
		ReadRootKey();
		break;
	case READ_PCH_OFFSET:
		ReadPchOfsets();
		break;
	case READ_BMC_OFFSET:
		ReadBmcOffets();
		break;
	case ENABLE_PIT_LEVEL_1_PROTECTION:
		// EnablePitLevel1();
		DEBUG_PRINTF("PIT IS NOT SUPPORTED");
		break;
	case ENABLE_PIT_LEVEL_2_PROTECTION:
		// EnablePitLevel2();
		DEBUG_PRINTF("PIT IS NOT SUPPORTED");
		break;
	}

	if ((gProvisionCount == 0x07) && (gProvisionData == 1)) {
		DEBUG_PRINTF("Calling provisioing process..");
		gProvisionData = 0;
		gProvisionCount = 0;
		Status = ProvisionRootKeyHash();
		if (Status != Success) {
			SetUfmStatusValue(COMMAND_ERROR);
			return;
		}

		Status = ProvisionPchOffsets();
		if (Status != Success) {
			SetUfmStatusValue(COMMAND_ERROR);
			return;
		}

		Status = ProvisionBmcOffsets();
		if (Status != Success) {
			DEBUG_PRINTF("Status: %x", Status);
			SetUfmStatusValue(COMMAND_ERROR);
			return;
		}

		SetUfmStatusValue(UFM_PROVISIONED);

		CPLD_STATUS cpld_status;

		ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, &cpld_status, sizeof(CPLD_STATUS));
		if (cpld_status.DecommissionFlag == TRUE) {
			cpld_status.DecommissionFlag = 0;
			ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, &cpld_status, sizeof(CPLD_STATUS));
		}
	}
}

/**
 * Function to update the Bmc Checkpoint
 * @Param  NULL
 * @retval NULL
 **/
void UpdateBmcCheckpoint(byte Data)
{
	if (gBmcBootDone == FALSE) {
		// Start WDT for BMC boot
		gBmcBootDone = START;
		gBMCWatchDogTimer = 0;
		SetBmcCheckpoint(Data);
	} else
		DEBUG_PRINTF("BMC boot completed. Checkpoint update not allowed");

	if (Data == PausingExecutionBlock) {
		DEBUG_PRINTF("Enter PausingExecution: Block Disable Timer");
		AspeedPFR_DisableTimer(BMC_EVENT);
	}
	if (Data == ResumedExecutionBlock)
		AspeedPFR_EnableTimer(BMC_EVENT);

	// BMC boot completed
	if (Data == CompletingexecutionBlock || Data == ReadToBootOS) {
		// If execution completed disable timer
		DEBUG_PRINTF("Enter Completingexecution: Block Disable Timer");
		AspeedPFR_DisableTimer(BMC_EVENT);
		gBmcBootDone = TRUE;
		gBMCWatchDogTimer = -1;
		SetPlatformState(T0_BMC_BOOTED);
	}
	if (Data == AUTHENTICATION_FAILED) {
		gBmcBootDone = FALSE;
		gBMCWatchDogTimer = BMC_MAXTIMEOUT;
	}
	if (gBmcBootDone == TRUE && gBiosBootDone == TRUE)
		SetPlatformState(T0_BOOT_COMPLETED);
}

void UpdateBiosCheckpoint(byte Data)
{
	if (gBiosBootDone == TRUE) {
		if (Data == EXECUTION_BLOCK_STARTED) {
			gBiosBootDone = FALSE;
			gObbBootDone = TRUE;
		}
	}
	if (gBiosBootDone == FALSE) {
		if (Data == EXECUTION_BLOCK_STARTED) {
			// Set max time for BIOS boot & starts timer
			gMaxTimeout = BIOS_MAXTIMEOUT;
			gBootCheckpointReceived = false;
			gBiosBootDone = START;
			gPCHWatchDogTimer = 0;
		}
	}
	if (Data == PausingExecutionBlock)
		AspeedPFR_DisableTimer(PCH_EVENT);
	if (Data == ResumedExecutionBlock)
		AspeedPFR_EnableTimer(PCH_EVENT);
	// BIOS boot completed
	if (Data == CompletingexecutionBlock || Data == ReadToBootOS) {
		AspeedPFR_DisableTimer(PCH_EVENT);
		gBiosBootDone = TRUE;
		gBootCheckpointReceived = true;
		gPCHWatchDogTimer = -1;
		SetPlatformState(T0_BIOS_BOOTED);
		DEBUG_PRINTF("BIOS boot completed. Checkpoint update not allowed");
	}
	if (Data == AUTHENTICATION_FAILED) {
		gBiosBootDone = FALSE;
		gPCHWatchDogTimer = gMaxTimeout;
		gBootCheckpointReceived = false;
		SetLastPanicReason(ACM_IBB_0BB_AUTH_FAIL);
	}
	if (gBmcBootDone == TRUE && gBiosBootDone == TRUE)
		SetPlatformState(T0_BOOT_COMPLETED);
	SetBiosCheckpoint(Data);
}

void PublishUpdateEvent(uint8_t ImageType, uint8_t FlashRegion)
{
	// Posting the Update signal
	UpdateActiveObject.type = ImageType;
	UpdateActiveObject.ProcessNewCommand = 1;

	UpdateEventData.operation = UPDATE_BACKUP;
	UpdateEventData.flash = FlashRegion;
	UpdateEventData.image = ImageType;

	if (post_smc_action(UPDATE, &UpdateActiveObject, &UpdateEventData)) {
		DEBUG_PRINTF("%s : event queue not available !", __func__);
		return;
	}
}

void UpdateIntentHandle(byte Data, uint32_t Source)
{
	uint8_t Index;
	uint8_t PchActiveStatus;
	uint8_t BmcActiveStatus;

	DEBUG_PRINTF(" Update Intent = 0x%x", Data);

	if (Data & UpdateAtReset) {
		// Getting cpld status from UFM

		ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, &cpld_update_status, sizeof(CPLD_STATUS));
		if (Data & PchActiveUpdate) {
			cpld_update_status.PchStatus = 1;
			cpld_update_status.Region[2].ActiveRegion = 1;
		}
		if (Data & PchRecoveryUpdate) {
			cpld_update_status.PchStatus = 1;
			cpld_update_status.Region[2].Recoveryregion = 1;
		}
		if (Data & HROTActiveUpdate) {
			cpld_update_status.CpldStatus = 1;
			cpld_update_status.CpldRecovery = 1;
			cpld_update_status.Region[0].ActiveRegion = 1;
		}
		if (Data & BmcActiveUpdate) {
			cpld_update_status.BmcStatus = 1;
			cpld_update_status.Region[1].ActiveRegion = 1;
		}
		if (Data & BmcRecoveryUpdate) {
			cpld_update_status.BmcStatus = 1;
			cpld_update_status.Region[1].Recoveryregion = 1;
		}
		if (Data & HROTRecoveryUpdate)
			DEBUG_PRINTF("HROTRecoveryUpdate not supported");
		if (Data & DymanicUpdate)
			DEBUG_PRINTF("DymanicUpdate not supported");
		// Setting updated cpld status to ufm
		ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, &cpld_update_status, sizeof(CPLD_STATUS));
	} else {
		if (Data & PchActiveUpdate) {
			if ((Data & PchActiveUpdate) && (Data & PchRecoveryUpdate)) {
				ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, &cpld_update_status, sizeof(CPLD_STATUS));
				cpld_update_status.PchStatus = 1;
				cpld_update_status.Region[2].ActiveRegion = 1;
				cpld_update_status.Region[2].Recoveryregion = 1;
				ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, &cpld_update_status, sizeof(CPLD_STATUS));
				PublishUpdateEvent(PCH_EVENT, PRIMARY_FLASH_REGION);
				return;
			}
			if (Source == BmcUpdateIntent) {
				ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, &cpld_update_status, sizeof(CPLD_STATUS));
				cpld_update_status.BmcToPchStatus = 1;
				ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, &cpld_update_status, sizeof(CPLD_STATUS));
			}

			PublishUpdateEvent(PCH_EVENT, PRIMARY_FLASH_REGION);
		}

		if (Data & PchRecoveryUpdate) {
			if (Source == BmcUpdateIntent) {
				ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, &cpld_update_status, sizeof(CPLD_STATUS));
				cpld_update_status.BmcToPchStatus = 1;
				ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, &cpld_update_status, sizeof(CPLD_STATUS));
			}
			PublishUpdateEvent(PCH_EVENT, SECONDARY_FLASH_REGION);
		}
		if (Data & HROTActiveUpdate)
			PublishUpdateEvent(ROT_TYPE, PRIMARY_FLASH_REGION);

		if (Data & BmcActiveUpdate) {
			if ((Data & BmcActiveUpdate) && (Data & BmcRecoveryUpdate)) {
				PublishUpdateEvent(BMC_EVENT, PRIMARY_FLASH_REGION);
				return;
			}
			PublishUpdateEvent(BMC_EVENT, PRIMARY_FLASH_REGION);
		}
		if (Data & BmcRecoveryUpdate)
			PublishUpdateEvent(BMC_EVENT, SECONDARY_FLASH_REGION);
		if (Data & HROTRecoveryUpdate)
			DEBUG_PRINTF("HROTRecoveryUpdate not supported");
		if (Data & DymanicUpdate)
			DEBUG_PRINTF("DymanicUpdate not supported");
	}

}

/**
 * Function to Check if system boots fine based on TimerISR
 * Returns Status
 */
bool WatchDogTimer(int ImageType)
{
	DEBUG_PRINTF("WDT Update Tiggers");
	if (ImageType == PCH_EVENT) {
		gPCHWatchDogTimer = 0;
		gBiosBootDone = FALSE;
	}
	if (ImageType == BMC_EVENT) {
		gBMCWatchDogTimer = 0;
		gBmcBootDone = FALSE;
	}

	gBootCheckpointReceived = false;
	gWDTUpdate = 1;

	return true;
}

static unsigned int mailBox_index = 0;
uint8_t PchBmcCommands(unsigned char *CipherText, uint8_t ReadFlag)
{

	byte DataToSend = 0;
	uint8_t i = 0;

	DEBUG_PRINTF("%s CipherText: %02x %02x", __func__, CipherText[0], CipherText[1]);

	switch (CipherText[0]) {
	case UfmCmdTriggerValue:
		if (CipherText[1] & EXECUTE_UFM_COMMAND) {       // If bit 0 set
			// Execute command specified at UFM/Provisioning Command register
			ClearUfmStatusValue(UFM_CLEAR_ON_NEW_COMMAND);
			SetUfmStatusValue(COMMAND_BUSY);
			process_provision_command();
			ClearUfmStatusValue(COMMAND_BUSY);
			SetUfmStatusValue(COMMAND_DONE);
		} else if (CipherText[1] & FLUSH_WRITE_FIFO) {    // Flush Write FIFO
			// Need to read UFM Write FIFO offest
			memset(&gUfmFifoData, 0, sizeof(gUfmFifoData));
			swmbx_flush_fifo(gSwMbxDev, UfmWriteFIFO);
			gFifoData = 0;
		} else if (CipherText[1] & FLUSH_READ_FIFO) {    // flush Read FIFO
			// Need to read UFM Read FIFO offest
			memset(&gReadFifoData, 0, sizeof(gReadFifoData));
			swmbx_flush_fifo(gSwMbxDev, UfmReadFIFO);
			gFifoData = 0;
			mailBox_index = 0;
		}
		break;
	case BmcCheckpoint:
		UpdateBmcCheckpoint(CipherText[1]);
		break;
	case AcmCheckpoint:
		// UpdateAcmCheckpoint(CipherText[1]);
		break;
	case BiosCheckpoint:
		UpdateBiosCheckpoint(CipherText[1]);
		break;
	case PchUpdateIntent:
		SetPchUpdateIntent(CipherText[1]);
		UpdateIntentHandle(CipherText[1], PchUpdateIntent);
		break;
	case BmcUpdateIntent:
		SetBmcUpdateIntent(CipherText[1]);
		UpdateIntentHandle(CipherText[1], BmcUpdateIntent);
		break;
	default:
		DEBUG_PRINTF("Mailbox command not found");
		break;
	}

	return DataToSend;
}
