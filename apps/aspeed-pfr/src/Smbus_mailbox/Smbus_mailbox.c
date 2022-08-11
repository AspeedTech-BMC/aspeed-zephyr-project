/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr.h>
#include <drivers/i2c.h>
#include <drivers/i2c/pfr/swmbx.h>
#include <logging/log.h>
#include <drivers/gpio.h>
#include <build_config.h>
#include "Smbus_mailbox.h"
#include "common/common.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_pfm_manifest.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_update.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#include "cerberus_pfr/cerberus_pfr_provision.h"
#include "cerberus_pfr/cerberus_pfr_update.h"
#endif
#include "pfr/pfr_ufm.h"

#include "AspeedStateMachine/AspeedStateMachine.h"

LOG_MODULE_REGISTER(mailbox, CONFIG_LOG_DEFAULT_LEVEL);

#if SMBUS_MAILBOX_DEBUG
#define DEBUG_PRINTF LOG_INF
#else
#define DEBUG_PRINTF(...)
#endif

#define READ_ONLY_RF_COUNT  20
#define READ_WRITE_RF_COUNT 6

#define PRIMARY_FLASH_REGION    1
#define SECONDARY_FLASH_REGION  2

static uint32_t gFailedUpdateAttempts = 0;
static SMBUS_MAIL_BOX gSmbusMailboxData = { 0 };
const struct device *gSwMbxDev = NULL;
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
int get_provision_data_in_flash(uint32_t addr, uint8_t *DataBuffer, uint32_t length)
{
	int status;
	struct spi_engine_wrapper *spi_flash = getSpiEngineWrapper();

	spi_flash->spi.device_id[0] = ROT_INTERNAL_INTEL_STATE; // Internal UFM SPI
	status = spi_flash->spi.base.read(&spi_flash->spi, addr, DataBuffer, length);

	if (status == 0)
		return Success;
	else
		return Failure;
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

#if defined(CONFIG_SEAMLESS_UPDATE)
#define TOTAL_MBOX_EVENT 10
#else
#define TOTAL_MBOX_EVENT 8
#endif

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

#if defined(CONFIG_SEAMLESS_UPDATE)
K_SEM_DEFINE(bmc_seamless_update_intent_sem, 0, 1);
K_SEM_DEFINE(pch_seamless_update_intent_sem, 0, 1);
#endif

void swmbx_notifyee_main(void *a, void *b, void *c)
{
	struct k_poll_event events[TOTAL_MBOX_EVENT];

	k_poll_event_init(&events[0], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &ufm_write_fifo_data_sem);
	k_poll_event_init(&events[1], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &ufm_read_fifo_state_sem);
	k_poll_event_init(&events[2], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &ufm_provision_trigger_sem);
	k_poll_event_init(&events[3], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &bmc_update_intent_sem);
	k_poll_event_init(&events[4], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &pch_update_intent_sem);
	k_poll_event_init(&events[5], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &bmc_checkpoint_sem);
	k_poll_event_init(&events[6], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &acm_checkpoint_sem);
	k_poll_event_init(&events[7], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &bios_checkpoint_sem);
#if defined(CONFIG_SEAMLESS_UPDATE)
	k_poll_event_init(&events[8], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &bmc_seamless_update_intent_sem);
	k_poll_event_init(&events[9], K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY, &pch_seamless_update_intent_sem);
#endif

	int ret;

	while (1) {
		ret = k_poll(events, TOTAL_MBOX_EVENT, K_FOREVER);

		union aspeed_event_data data = {0};
		if (ret < 0) {
			DEBUG_PRINTF("k_poll error ret=%d", ret);
			continue;
		}

		if (events[0].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* UFM Write FIFO from BMC/PCH */
			k_sem_take(events[0].sem, K_NO_WAIT);
			// TODO: race condition
			do {
				uint8_t c;

				ret = swmbx_read(gSwMbxDev, true, UfmWriteFIFO, &c);
				if (!ret) {
					gUfmFifoData[gFifoData++] = c;
				}
			} while (!ret);
		} else if (events[1].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* UFM Read FIFO empty prepare next data */
			k_sem_take(events[1].sem, K_NO_WAIT);
		} else if (events[2].state == K_POLL_STATE_SEM_AVAILABLE) {

			/* UFM Provision Trigger */
			k_sem_take(events[2].sem, K_NO_WAIT);
			data.bit8[0] = UfmCmdTriggerValue;
			swmbx_get_msg(0, UfmCmdTriggerValue, &data.bit8[1]);

			GenerateStateMachineEvent(PROVISION_CMD, data.ptr);
		} else if (events[3].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* BMC Update Intent */
			k_sem_take(events[3].sem, K_NO_WAIT);
			data.bit8[0] = BmcUpdateIntent;
			swmbx_get_msg(0, BmcUpdateIntent, &data.bit8[1]);

			GenerateStateMachineEvent(UPDATE_REQUESTED, data.ptr);
		} else if (events[4].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* PCH Update Intent */
			k_sem_take(events[4].sem, K_NO_WAIT);
			data.bit8[0] = PchUpdateIntent;
			swmbx_get_msg(0, PchUpdateIntent, &data.bit8[1]);

			GenerateStateMachineEvent(UPDATE_REQUESTED, data.ptr);
		} else if (events[5].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* BMC Checkpoint */
			k_sem_take(events[5].sem, K_NO_WAIT);
			data.bit8[0] = BmcCheckpoint;
			swmbx_get_msg(0, BmcCheckpoint, &data.bit8[1]);

			GenerateStateMachineEvent(WDT_CHECKPOINT, data.ptr);
		} else if (events[6].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* ACM Checkpoint */
			k_sem_take(events[6].sem, K_NO_WAIT);
			data.bit8[0] = AcmCheckpoint;
			swmbx_get_msg(0, AcmCheckpoint, &data.bit8[1]);

			GenerateStateMachineEvent(WDT_CHECKPOINT, NULL);
		} else if (events[7].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* BIOS Checkpoint */
			k_sem_take(events[7].sem, K_NO_WAIT);
			data.bit8[0] = BiosCheckpoint;
			swmbx_get_msg(0, BiosCheckpoint, &data.bit8[1]);

			GenerateStateMachineEvent(WDT_CHECKPOINT, NULL);
		}
#if defined(CONFIG_SEAMLESS_UPDATE)
		else if (events[8].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* BMC Seamless Update Intent */
			k_sem_take(events[8].sem, K_NO_WAIT);
			data.bit8[0] = BmcSeamlessUpdateIntent;
			swmbx_get_msg(0, BmcSeamlessUpdateIntent, &data.bit8[1]);

			GenerateStateMachineEvent(SEAMLESS_UPDATE_REQUESTED, data.ptr);
		} else if (events[9].state == K_POLL_STATE_SEM_AVAILABLE) {
			/* PCH Seamless Update Intent */
			k_sem_take(events[9].sem, K_NO_WAIT);
			data.bit8[0] = PchSeamlessUpdateIntent;
			swmbx_get_msg(0, PchSeamlessUpdateIntent, &data.bit8[1]);

			GenerateStateMachineEvent(SEAMLESS_UPDATE_REQUESTED, data.ptr);
		}
#endif

		for (size_t i = 0; i < TOTAL_MBOX_EVENT; ++i)
			events[i].state = K_POLL_STATE_NOT_READY;
	}
}

void InitializeSoftwareMailbox(void)
{
	/* Top level mailbox device driver */
	const struct device *swmbx_dev = NULL;
	int result;

	swmbx_dev = device_get_binding("SWMBX");
	if (swmbx_dev == NULL) {
		DEBUG_PRINTF("%s: fail to bind %s", __FUNCTION__, "SWMBX");
		return;
	}
	gSwMbxDev = swmbx_dev;

	/* Enable mailbox read/write notifiaction and FIFO */
	swmbx_enable_behavior(swmbx_dev, SWMBX_PROTECT | SWMBX_NOTIFY | SWMBX_FIFO, 1);

	/* Register mailbox notification semphore */
	swmbx_update_fifo(swmbx_dev, &ufm_write_fifo_state_sem, 0, UfmWriteFIFO, 0x40, SWMBX_FIFO_NOTIFY_STOP, true);
	swmbx_update_fifo(swmbx_dev, &ufm_read_fifo_state_sem, 1, UfmReadFIFO, 0x40, SWMBX_FIFO_NOTIFY_STOP, true);

	/* swmbx_update_notify(dev, port, sem, addr, enable) */
	/* From BMC */
	swmbx_update_notify(swmbx_dev, 0x0, &ufm_write_fifo_data_sem, UfmWriteFIFO, true);
	swmbx_update_notify(swmbx_dev, 0x0, &ufm_provision_trigger_sem, UfmCmdTriggerValue, true);
	swmbx_update_notify(swmbx_dev, 0x0, &bmc_update_intent_sem, BmcUpdateIntent, true);
	swmbx_update_notify(swmbx_dev, 0x0, &bmc_checkpoint_sem, BmcCheckpoint, true);
#if defined(CONFIG_SEAMLESS_UPDATE)
	swmbx_update_notify(swmbx_dev, 0x0, &bmc_seamless_update_intent_sem,
			BmcSeamlessUpdateIntent, true);
#endif

	/* From PCH */
	swmbx_update_notify(swmbx_dev, 0x1, &ufm_write_fifo_data_sem, UfmWriteFIFO, true);
	swmbx_update_notify(swmbx_dev, 0x1, &ufm_provision_trigger_sem, UfmCmdTriggerValue, true);
	swmbx_update_notify(swmbx_dev, 0x1, &pch_update_intent_sem, PchUpdateIntent, true);
	swmbx_update_notify(swmbx_dev, 0x1, &acm_checkpoint_sem, AcmCheckpoint, true);
	swmbx_update_notify(swmbx_dev, 0x1, &bios_checkpoint_sem, BiosCheckpoint, true);
#if defined(CONFIG_SEAMLESS_UPDATE)
	swmbx_update_notify(swmbx_dev, 0x1, &pch_seamless_update_intent_sem,
			PchSeamlessUpdateIntent, true);
#endif

	/* Protect bit:
	 * 0 means readable/writable
	 * 1 means read-only
	 *
	 * Port and access_control[]:
	 * 0 for BMC
	 * 1 for PCH
	 */
	uint32_t access_control[2][8] = {
		/* BMC */
		{
			0xfff704ff, // 1fh ~ 00h
			0xffffffff, // 3fh ~ 20h CPLD RoT Hash
			0xffffffff, // 5fh ~ 40h CPLD RoT Hash
			0xfffffffa, // 7fh ~ 60h
			0xffffffff, // 9fh ~ 80h ACM/BIOS Scrachpad
			0xffffffff, // bfh ~ a0h ACM/BIOS Scrachpad
			0x00000000, // dfh ~ c0h BMC scrachpad
			0x00000000, // ffh ~ e0h BMC scrachpad
		},
		/* PCH */
		{
			0xfff884ff, // 1fh ~ 00h
			0xffffffff, // 3fh ~ 20h CPLD RoT Hash
			0xffffffff, // 5fh ~ 40h CPLD RoT Hash
			0xfffffff5, // 7fh ~ 60h
			0x00000000, // 9fh ~ 80h ACM/BIOS Scrachpad
			0x00000000, // bfh ~ a0h ACM/BIOS Scrachpad
			0xffffffff, // dfh ~ c0h BMC scrachpad
			0xffffffff, // ffh ~ e0h BMC scrachpad
		},
	};
	result = swmbx_apply_protect(swmbx_dev, 0, access_control[0], 0, 8);
	LOG_INF("Mailbox protection apply result=%d", result);
	result = swmbx_apply_protect(swmbx_dev, 1, access_control[1], 0, 8);
	LOG_INF("Mailbox protection apply result=%d", result);

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
	SetCpldReleaseVersion((PROJECT_VERSION_MAJOR << 4) | PROJECT_VERSION_MINOR);

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
MBX_REG_GETTER(PlatformState);
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

#if defined(CONFIG_FRONT_PANEL_LED)
#include <drivers/timer/aspeed_timer.h>
#include <drivers/led.h>

#define GPIO_SPEC(node_id) GPIO_DT_SPEC_GET_OR(node_id, gpios, {0})
#define LED_DEVICE "leds"
#define TIMER_DEVICE "TIMER0"

static struct aspeed_timer_user_config timer_conf;
static const struct device *led_dev = NULL;
static const struct device *led_timer_dev = NULL;
static const struct device *bmc_fp_green_in = NULL;
static const struct device *bmc_fp_amber_in = NULL;
static bool fp_green_on;
static bool fp_amber_on;
static bool bypass_bmc_fp_signal;

static const struct gpio_dt_spec bmc_fp_green = GPIO_SPEC(DT_ALIAS(fp_input0));
static const struct gpio_dt_spec bmc_fp_amber = GPIO_SPEC(DT_ALIAS(fp_input1));

static struct gpio_callback bmc_fp_green_cb_data;
static struct gpio_callback bmc_fp_amber_cb_data;

enum {
	FP_GREEN_LED  = 0x00,
	FP_AMBER_LED,
};

enum {
	ONE_SHOT_TIMER = 0x00,
	PERIOD_TIMER,
};

void fp_amber_led_ctrl_callback()
{
	fp_amber_on ? led_off(led_dev, FP_AMBER_LED) : led_on(led_dev, FP_AMBER_LED);
	fp_amber_on = !fp_amber_on;
}

void bmc_fp_led_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	int led_id;
	if (bypass_bmc_fp_signal)
		return;

	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	if (gpio_pin == bmc_fp_green.pin)
		led_id = FP_GREEN_LED;
	else if (gpio_pin == bmc_fp_amber.pin)
		led_id = FP_AMBER_LED;
	else
		return;

	int ret = gpio_pin_get(dev, gpio_pin);
	if (ret < 0) {
		LOG_ERR("Failed to get BMC_FP_GREEN_LED status");
		return;
	}

	ret ? led_on(led_dev, led_id) : led_off(led_dev, led_id);
	if (led_id == FP_GREEN_LED)
		fp_green_on = (bool)ret;
	else
		fp_amber_on = (bool)ret;
}

void initializeFPLEDs(void)
{
	// init led
	led_dev = device_get_binding(LED_DEVICE);
	led_off(led_dev, FP_GREEN_LED);
	fp_green_on = false;
	led_off(led_dev, FP_AMBER_LED);
	fp_amber_on = false;

	// init timer
	led_timer_dev = device_get_binding(TIMER_DEVICE);
	timer_conf.millisec = 500;
	timer_conf.timer_type = PERIOD_TIMER;
	timer_conf.user_data = NULL;
	timer_conf.callback = fp_amber_led_ctrl_callback;

	// init bmc_fp_green_led
	bmc_fp_green_in = device_get_binding(DT_GPIO_LABEL(DT_ALIAS(fp_input0), gpios));
	gpio_pin_configure(bmc_fp_green_in, DT_GPIO_PIN(DT_ALIAS(fp_input0), gpios),
			DT_GPIO_FLAGS(DT_ALIAS(fp_input0), gpios) | GPIO_INPUT);
	gpio_pin_interrupt_configure(bmc_fp_green_in, DT_GPIO_PIN(DT_ALIAS(fp_input0), gpios),
			GPIO_INT_EDGE_BOTH);
	gpio_init_callback(&bmc_fp_green_cb_data, bmc_fp_led_handler,
			BIT(DT_GPIO_PIN(DT_ALIAS(fp_input0), gpios)));
	gpio_add_callback(bmc_fp_green_in, &bmc_fp_green_cb_data);

	// init bmc_fp_amber_led
	bmc_fp_amber_in = device_get_binding(DT_GPIO_LABEL(DT_ALIAS(fp_input1), gpios));
	gpio_pin_configure(bmc_fp_amber_in, DT_GPIO_PIN(DT_ALIAS(fp_input1), gpios),
			DT_GPIO_FLAGS(DT_ALIAS(fp_input1), gpios) | GPIO_INPUT);
	gpio_pin_interrupt_configure(bmc_fp_amber_in, DT_GPIO_PIN(DT_ALIAS(fp_input1), gpios),
			GPIO_INT_EDGE_BOTH);
	gpio_init_callback(&bmc_fp_amber_cb_data, bmc_fp_led_handler,
			BIT(DT_GPIO_PIN(DT_ALIAS(fp_input1), gpios)));
	gpio_add_callback(bmc_fp_amber_in, &bmc_fp_amber_cb_data);
}

void SetFPLEDState(byte PlatformStateData)
{
	// FP LED behavior
	//
	// |  Green  |  Amber  | State    |
	// --------------------------------
	// |   Lit   |  Off    | Verify   |
	// |   Off   |  Blink  | Recovery |
	// |   Off   |  Lit    | Update   |
	// | PassThr | PassThr | Tzero    |
	if (PlatformStateData == PCH_FW_UPDATE ||
	    PlatformStateData == BMC_FW_UPDATE ||
	    PlatformStateData == CPLD_FW_UPDATE) {
		bypass_bmc_fp_signal = true;
		timer_aspeed_stop(led_timer_dev);
		led_off(led_dev, FP_GREEN_LED);
		fp_green_on = false;
		led_on(led_dev, FP_AMBER_LED);
		fp_amber_on = true;
	} else if (PlatformStateData == T_MINUS_1_FW_RECOVERY) {
		bypass_bmc_fp_signal = true;
		led_off(led_dev, FP_GREEN_LED);
		fp_green_on = false;
		timer_aspeed_start(led_timer_dev, &timer_conf);
	} else if (PlatformStateData == ENTER_T_MINUS_1) {
		bypass_bmc_fp_signal = true;
		timer_aspeed_stop(led_timer_dev);
		led_on(led_dev, FP_GREEN_LED);
		fp_green_on = true;
		led_off(led_dev, FP_AMBER_LED);
		fp_amber_on = false;
	} else if (PlatformStateData == ENTER_T0) {
		timer_aspeed_stop(led_timer_dev);
		bypass_bmc_fp_signal = false;
		int pin_state = gpio_pin_get(bmc_fp_green_in, bmc_fp_green.pin);
		if (pin_state < 0) {
			LOG_ERR("Failed to get BMC_FP_GREEN_LED");
			return;
		}
		pin_state ? led_on(led_dev, FP_GREEN_LED) : led_off(led_dev, FP_GREEN_LED);
		fp_green_on = pin_state;

		pin_state = gpio_pin_get(bmc_fp_amber_in, bmc_fp_amber.pin);
		if (pin_state < 0) {
			LOG_ERR("Failed to get BMC_FP_AMBER_LED");
			return;
		}
		pin_state ? led_on(led_dev, FP_AMBER_LED) : led_off(led_dev, FP_AMBER_LED);
		fp_amber_on = pin_state;
	}
}
#endif

void SetPlatformState(byte PlatformStateData)
{
#if defined(CONFIG_PLATFORM_STATE_LED)
	static const struct gpio_dt_spec leds[] = {
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), platform_state_out_gpios, 0),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), platform_state_out_gpios, 1),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), platform_state_out_gpios, 2),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), platform_state_out_gpios, 3),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), platform_state_out_gpios, 4),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), platform_state_out_gpios, 5),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), platform_state_out_gpios, 6),
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), platform_state_out_gpios, 7)};

	for(uint8_t bit = 0; bit < 8; ++bit) {
		gpio_pin_configure_dt(&leds[bit], GPIO_OUTPUT);
		gpio_pin_set(leds[bit].port, leds[bit].pin, !(PlatformStateData & BIT(bit)));
	}
#endif

#if defined(CONFIG_FRONT_PANEL_LED)
	SetFPLEDState(PlatformStateData);
#endif
	swmbx_write(gSwMbxDev, false, PlatformState, &PlatformStateData);
}

int getFailedUpdateAttemptsCount(void)
{
	return gFailedUpdateAttempts;
}

void LogErrorCodes(uint8_t major_err, uint8_t minor_err)
{
	SetMajorErrorCode(major_err);
	SetMinorErrorCode(minor_err);
}

void LogUpdateFailure(uint8_t minor_err, uint32_t failed_count)
{
	LogErrorCodes(FW_UPDATE_FAIL, minor_err);
	gFailedUpdateAttempts += failed_count;
}

void ClearUpdateFailure(void)
{
	if (GetMajorErrorCode() == FW_UPDATE_FAIL)
		LogErrorCodes(0, 0);
	gFailedUpdateAttempts = 0;
}

void LogLastPanic(uint8_t panic)
{
	SetLastPanicReason(panic);
	IncPanicEventCount();
}

void LogRecovery(uint8_t reason)
{
	SetLastRecoveryReason(reason);
	IncRecoveryCount();
}

void LogWatchdogRecovery(uint8_t recovery_reason, uint8_t panic_reason)
{
	LogRecovery(recovery_reason);
	LogLastPanic(panic_reason);
}

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
	set_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, 4);
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
	uint8_t HashData[SHA384_DIGEST_LENGTH] = { 0 };

	memcpy(HashData, gSmbusMailboxData.CpldFPGARoTHash, SHA384_DIGEST_LENGTH);
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
		Status = set_provision_data_in_flash(ROOT_KEY_HASH, (uint8_t *)gRootKeyHash, SHA384_DIGEST_LENGTH);
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
		Status = set_provision_data_in_flash(PCH_ACTIVE_PFM_OFFSET, (uint8_t *)gPchOffsets, sizeof(gPchOffsets));
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
		Status = set_provision_data_in_flash(BMC_ACTIVE_PFM_OFFSET, (uint8_t *)gBmcOffsets, sizeof(gBmcOffsets));
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

		ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_status, sizeof(CPLD_STATUS));
		if (cpld_status.DecommissionFlag == TRUE) {
			cpld_status.DecommissionFlag = 0;
			ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_status, sizeof(CPLD_STATUS));
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
	if (Data == CompletingExecutionBlock || Data == ReadToBootOS) {
		// If execution completed disable timer
		DEBUG_PRINTF("Enter CompletingExecution: Block Disable Timer");
		AspeedPFR_DisableTimer(BMC_EVENT);
		gBmcBootDone = TRUE;
		gBMCWatchDogTimer = -1;
#if defined(CONFIG_BMC_CHECKPOINT_RECOVERY) && defined(CONFIG_INTEL_PFR)
		reset_recovery_level(BMC_SPI);
#endif
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
	if (Data == CompletingExecutionBlock || Data == ReadToBootOS) {
		AspeedPFR_DisableTimer(PCH_EVENT);
		gBiosBootDone = TRUE;
		gBootCheckpointReceived = true;
		gPCHWatchDogTimer = -1;
		SetPlatformState(T0_BIOS_BOOTED);
#if defined(CONFIG_PCH_CHECKPOINT_RECOVERY) && defined(CONFIG_INTEL_PFR)
		reset_recovery_level(PCH_SPI);
#endif
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

