/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr.h>
#include <smf.h>
#include <shell/shell.h>
#include <logging/log.h>
#include <logging/log_ctrl.h>
#include <drivers/i2c/pfr/swmbx.h>
#include <drivers/misc/aspeed/abr_aspeed.h>
#include <drivers/flash.h>

#include "AspeedStateMachine.h"
#include "include/SmbusMailBoxCom.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_update.h"
#include "imageRecovery/image_recovery.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "StateMachineAction/StateMachineActions.h"
#include "pfr/pfr_util.h"
#include "gpio/gpio_aspeed.h"
#include "logging/logging_wrapper.h"
#include "manifestProcessor/manifestProcessor.h"
#include "pfr/pfr_recovery.h"
#include "pfr/pfr_verification.h"
#include "platform_monitor/platform_monitor.h"
#include "platform_monitor/spim_monitor.h"
#include "engineManager/engine_manager.h"
#include "spi_filter/spi_filter_wrapper.h"
#include "pfr/pfr_ufm.h"
#include "flash/flash_aspeed.h"
#include "flash/flash_wrapper.h"

LOG_MODULE_REGISTER(aspeed_state_machine, LOG_LEVEL_DBG);
K_FIFO_DEFINE(aspeed_sm_fifo);
struct smf_context s_obj;
static const struct smf_state state_table[];

enum aspeed_pfr_event event_log[128] = {START_STATE_MACHINE};
size_t event_log_idx = 0;

extern enum boot_indicator get_boot_indicator(void);

void GenerateStateMachineEvent(enum aspeed_pfr_event evt, void *data)
{
	struct event_context *event = (struct event_context *)k_malloc(sizeof(struct event_context));

	LOG_INF("Send event:%d data:%p to state machine", evt, data);
	event_log[event_log_idx % 128] = evt;
	event_log_idx++;
	event->event = evt;
	event->data.ptr = data;

	k_fifo_put(&aspeed_sm_fifo, event);
}

void do_init(void *o)
{
	struct smf_context *state = (struct smf_context *)o;

	LOG_DBG("Start");

#if defined(CONFIG_FRONT_PANEL_LED)
	initializeFPLEDs();
#endif
	initializeEngines();
	initializeManifestProcessor();
	debug_log_init();// State Machine log saving
	spim_irq_init();

	// DEBUG_HALT();
	pfr_bmc_srst_enable_ctrl(true);
	BMCBootHold();
	PCHBootHold();

	state->bmc_active_object.type = BMC_EVENT;
	state->bmc_active_object.ActiveImageStatus = Failure;
	state->bmc_active_object.RecoveryImageStatus = Failure;
	state->bmc_active_object.RestrictActiveUpdate = 0;

	state->pch_active_object.type = PCH_EVENT;
	state->pch_active_object.ActiveImageStatus = Failure;
	state->pch_active_object.RecoveryImageStatus = Failure;
	state->pch_active_object.RestrictActiveUpdate = 0;

	// I2c_slave_dev_debug+>
	// struct i2c_slave_interface *I2CSlaveEngine = getI2CSlaveEngineInstance();
	// struct I2CSlave_engine_wrapper *I2cSlaveEngineWrapper;

	// I2C_Slave_wrapper_init(getI2CSlaveEngineInstance());

	enum boot_indicator rot_boot_from = get_boot_indicator();

	disable_abr_wdt();

	if (rot_boot_from == BOOT_FROM_ALTERNATE_PART) {
		/* ABR secondary booted, copy recovery image to active image */
		LOG_ERR("ROT boot from secondary image, need to recovery ROT active region");
		GenerateStateMachineEvent(INIT_ROT_SECONDARY_BOOTED, NULL);
	} else {
		/* ABR primary booted */
#if SMBUS_MAILBOX_SUPPORT
		InitializeSmbusMailbox();
#endif

		SetPlatformState(CPLD_NIOS_II_PROCESSOR_WAITING_TO_START);
#if defined(CONFIG_INIT_POWER_SEQUENCE)
		LOG_INF("Wait for power sequence");
		power_sequence();
#else
		GenerateStateMachineEvent(INIT_DONE, NULL);
		SetPlatformState(CPLD_NIOS_II_PROCESSOR_STARTED);
#endif
	}
	LOG_DBG("End");
}

void enter_tmin1(void *o)
{
	ARG_UNUSED(o);
	LOG_DBG("Start");
	SetPlatformState(ENTER_T_MINUS_1);
	/* TODO: BMC only reset */
	BMCBootHold();
	PCHBootHold();
	LOG_DBG("End");
}

void handle_image_verification(void *o)
{
	struct smf_context *state = (struct smf_context *)o;
	struct event_context *evt_ctx = ((struct smf_context *)o)->event_ctx;
	int ret;


	byte provision_state = GetUfmStatusValue();

	if (!(provision_state & UFM_PROVISIONED)) {
		// Unprovisioned, populate INIT_UNPROVISIONED event will enter UNPROVISIONED state
		GenerateStateMachineEvent(VERIFY_UNPROVISIONED, NULL);
	} else {
		/* Check pending firmware update (update at reset) */
		CPLD_STATUS cpld_update_status;
		bool update_reset = false;

		ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
		if (cpld_update_status.CpldStatus == 1
				|| cpld_update_status.BmcStatus == 1
				|| cpld_update_status.PchStatus == 1) {
			uint8_t intent = 0x00;

			if (cpld_update_status.CpldStatus == 1) {
				if (cpld_update_status.Region[0].ActiveRegion == 1)
					intent |= HROTActiveUpdate;
				if (cpld_update_status.Region[0].Recoveryregion == 1)
					intent |= HROTRecoveryUpdate;
				cpld_update_status.CpldStatus = 0;
				cpld_update_status.Region[0].ActiveRegion = 0;
				cpld_update_status.Region[0].Recoveryregion = 0;
			}

			if (cpld_update_status.BmcStatus == 1) {
				if (cpld_update_status.Region[1].ActiveRegion == 1)
					intent |= BmcActiveUpdate;
				if (cpld_update_status.Region[1].Recoveryregion == 1)
					intent |= BmcRecoveryUpdate;
				cpld_update_status.BmcStatus = 0;
				cpld_update_status.Region[1].ActiveRegion = 0;
				cpld_update_status.Region[1].Recoveryregion = 0;
			}

			if (cpld_update_status.PchStatus == 1) {
				if (cpld_update_status.Region[2].ActiveRegion == 1)
					intent |= PchActiveUpdate;
				if (cpld_update_status.Region[2].Recoveryregion == 1)
					intent |= PchRecoveryUpdate;
				cpld_update_status.PchStatus = 0;
				cpld_update_status.Region[2].ActiveRegion = 0;
				cpld_update_status.Region[2].Recoveryregion = 0;
			}

			/* Clear the pending flags */
			ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));

			if (intent) {
				union aspeed_event_data data;

				update_reset = true;
				data.bit8[0] = BmcUpdateIntent;
				data.bit8[1] = intent;
				GenerateStateMachineEvent(UPDATE_REQUESTED, data.ptr);
			}
		}

		/* No pending update, verify images */
		if (update_reset == false) {
			/* BMC Verification */
			SetPlatformState(BMC_FLASH_AUTH);
			{
				EVENT_CONTEXT evt_wrap;

				evt_wrap.image = BMC_EVENT;
				evt_wrap.operation = VERIFY_BACKUP;
				evt_wrap.flash = SECONDARY_FLASH_REGION;
				ret = authentication_image(NULL, &evt_wrap);
				LOG_INF("authentication_image bmc backup return %d", ret);
				if (ret == 0)
					state->bmc_active_object.RecoveryImageStatus = Success;
				else
					state->bmc_active_object.RecoveryImageStatus = Failure;
			}

			{
				EVENT_CONTEXT evt_wrap;

				evt_wrap.image = BMC_EVENT;
				evt_wrap.operation = VERIFY_ACTIVE;
				evt_wrap.flash = PRIMARY_FLASH_REGION;
				ret = authentication_image(NULL, &evt_wrap);
				LOG_INF("authentication_image bmc active return %d", ret);
				if (ret == 0)
					state->bmc_active_object.ActiveImageStatus = Success;
				else
					state->bmc_active_object.ActiveImageStatus = Failure;
			}

			/* PCH Verification */
			SetPlatformState(PCH_FLASH_AUTH);
			{
				EVENT_CONTEXT evt_wrap;

				evt_wrap.image = PCH_EVENT;
				evt_wrap.operation = VERIFY_BACKUP;
				evt_wrap.flash = SECONDARY_FLASH_REGION;
				ret = authentication_image(NULL, &evt_wrap);
				LOG_INF("authentication_image host backup return %d", ret);
				if (ret == 0)
					state->pch_active_object.RecoveryImageStatus = Success;
				else
					state->pch_active_object.RecoveryImageStatus = Failure;
			}

			{
				EVENT_CONTEXT evt_wrap;

				evt_wrap.image = PCH_EVENT;
				evt_wrap.operation = VERIFY_ACTIVE;
				evt_wrap.flash = PRIMARY_FLASH_REGION;
				ret = authentication_image(NULL, &evt_wrap);
				LOG_INF("authentication_image host active return %d", ret);
				if (ret == 0)
					state->pch_active_object.ActiveImageStatus = Success;
				else
					state->pch_active_object.ActiveImageStatus = Failure;
			}
			/* Success = 0, Failure = 1 */
			LOG_INF("BMC image verification recovery=%s active=%s",
					state->bmc_active_object.RecoveryImageStatus ? "Bad" : "Good",
					state->bmc_active_object.ActiveImageStatus ? "Bad" : "Good");
			LOG_INF("PCH image verification recovery=%s active=%s",
					state->pch_active_object.RecoveryImageStatus ? "Bad" : "Good",
					state->pch_active_object.ActiveImageStatus ? "Bad" : "Good");

			if (evt_ctx->event != RECOVERY_DONE) {
				if (state->pch_active_object.ActiveImageStatus == Failure
						|| state->bmc_active_object.ActiveImageStatus == Failure
						|| state->pch_active_object.RecoveryImageStatus == Failure
						|| state->bmc_active_object.RecoveryImageStatus == Failure) {
					/* ACT/RCV region went wrong, go recovery */
					GenerateStateMachineEvent(VERIFY_FAILED, NULL);
				} else {
					/* Everything good, done */
					GenerateStateMachineEvent(VERIFY_DONE, NULL);
				}
			} else {
				/* Coming back from RECOVERY, relax some condition */
				if (state->bmc_active_object.ActiveImageStatus == Success) {
					/* If BMC is good to go, just boot the BMC. It wiil be checked by Tzero */
					GenerateStateMachineEvent(VERIFY_DONE, NULL);
				} else {
					/* SYSTEM LOCKDOWN */
					GenerateStateMachineEvent(RECOVERY_FAILED, NULL);
				}
			}
		}
	}
}

void do_verify(void *o)
{
	LOG_DBG("Start");
	handle_image_verification(o);
	LOG_DBG("End");
}

void handle_recovery(void *o)
{
	struct smf_context *state = (struct smf_context *)o;
	struct event_context *evt_ctx = state->event_ctx;

	/* Check Staging Image */
	bool recovery_done = 0;
	int ret;
	EVENT_CONTEXT evt_wrap;

	recovery_initialize();

	/* TODO: Verify Staging? */
	SetPlatformState(T_MINUS_1_FW_RECOVERY);
	switch (evt_ctx->event) {
#if defined(CONFIG_BMC_CHECKPOINT_RECOVERY) || defined(CONFIG_PCH_CHECKPOINT_RECOVERY)
	case WDT_TIMEOUT:
		// WDT Checkpoint Timeout
		SetPlatformState(WDT_TIMEOUT_RECOVERY);
#if defined(CONFIG_BMC_CHECKPOINT_RECOVERY)
		if (evt_ctx->data.bit8[0] == BMC_EVENT)
			state->bmc_active_object.ActiveImageStatus = Failure;
#endif
#if defined(CONFIG_PCH_CHECKPOINT_RECOVERY)
		if (evt_ctx->data.bit8[0] == PCH_EVENT)
			state->pch_active_object.ActiveImageStatus = Failure;
#endif
		__attribute__ ((fallthrough));
#endif
	case VERIFY_FAILED:
		// Recovery matrix can be handled in recover_image
		if (state->bmc_active_object.RecoveryImageStatus == Failure) {
			evt_wrap.image = BMC_EVENT;
			ret = recover_image(&state->bmc_active_object, &evt_wrap);

			LOG_INF("BMC recover recovery region return=%d", ret);
			if (ret == Success || ret == VerifyActive || ret == VerifyRecovery)
				recovery_done = 1;
		}

		if (state->bmc_active_object.ActiveImageStatus == Failure) {
			evt_wrap.image = BMC_EVENT;
			ret = recover_image(&state->bmc_active_object, &evt_wrap);
			LOG_INF("BMC recover active region return=%d", ret);
			if (ret == Success || ret == VerifyActive || ret == VerifyRecovery)
				recovery_done = 1;

		}

		if (state->pch_active_object.RecoveryImageStatus == Failure) {
			evt_wrap.image = PCH_EVENT;
			ret = recover_image(&state->pch_active_object, &evt_wrap);
			LOG_INF("PCH Recovery return=%d", ret);
			recovery_done = 1;
		}

		if (state->pch_active_object.ActiveImageStatus == Failure) {
			evt_wrap.image = PCH_EVENT;
			ret = recover_image(&state->pch_active_object, &evt_wrap);
			LOG_INF("PCH Recovery return=%d", ret);
			recovery_done = 1;
		}
		break;
	default:
		break;
	}

	if (recovery_done)
		GenerateStateMachineEvent(RECOVERY_DONE, NULL);
	else
		GenerateStateMachineEvent(RECOVERY_FAILED, NULL);
}

void do_recovery(void *o)
{
	LOG_DBG("Start");
	handle_recovery(o);
	LOG_DBG("End");
}

void do_rot_recovery(void *o)
{
	ARG_UNUSED(o);
	LOG_DBG("Start");
	uint8_t status;
	uint32_t region_size = pfr_spi_get_device_size(ROT_INTERNAL_RECOVERY);

	clear_abr_indicator();

	LOG_INF("Erase PFR Active region size=%08x", region_size);
	if (pfr_spi_erase_region(ROT_INTERNAL_ACTIVE, true, 0, region_size)) {
		LOG_ERR("Erase PFR active region failed, SYSTEM LOCKDOWN");
		GenerateStateMachineEvent(RECOVERY_FAILED, NULL);
	}

	LOG_INF("Copy PFR Recovery region to Active region");
	status = pfr_spi_region_read_write_between_spi(ROT_INTERNAL_RECOVERY, 0,
			ROT_INTERNAL_ACTIVE, 0, region_size);

	if (!status) {
		LOG_INF("Copy PFR Recovery region to Active region done");
		GenerateStateMachineEvent(RECOVERY_DONE, NULL);
	} else {
		LOG_ERR("Recover PFR active region failed, SYSTEM LOCKDOWN");
		GenerateStateMachineEvent(RECOVERY_FAILED, NULL);
	}
	LOG_DBG("End");
}

void enter_tzero(void *o)
{
	LOG_DBG("Start");
	SetPlatformState(ENTER_T0);

	struct smf_context *state = (struct smf_context *)o;
	/* Arm reset monitor */
	platform_monitor_init();
#if defined(CONFIG_ASPEED_DC_SCM)
	pfr_bmc_srst_enable_ctrl(false);
#endif
	if (state->ctx.current == &state_table[RUNTIME]) {
		/* Provisioned */
		/* Releasing System Reset */
		if (state->bmc_active_object.ActiveImageStatus == Success) {
			/* Arm SPI/I2C Filter */
			apply_pfm_protection(BMC_SPI);
			BMCBootRelease();
		} else {
			/* Should not enter here, redirect to LOCKDOWN */
			LOG_ERR("BMC firmware is invalid, lockdown the platform");
		}

		if (state->pch_active_object.ActiveImageStatus == Success) {
			/* Arm SPI/I2C Filter */
			apply_pfm_protection(PCH_SPI);
			PCHBootRelease();
		}
		else
			LOG_ERR("Host firmware is invalid, host won't boot");
	} else {
		/* Unprovisioned - Releasing System Reset */
		Set_SPI_Filter_RW_Region("spi_m1", SPI_FILTER_READ_PRIV, SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
		Set_SPI_Filter_RW_Region("spi_m1", SPI_FILTER_WRITE_PRIV, SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
		SPI_Monitor_Enable("spi_m1", false);
		Set_SPI_Filter_RW_Region("spi_m2", SPI_FILTER_READ_PRIV, SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
		Set_SPI_Filter_RW_Region("spi_m2", SPI_FILTER_WRITE_PRIV, SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
		SPI_Monitor_Enable("spi_m2", false);
		Set_SPI_Filter_RW_Region("spi_m3", SPI_FILTER_READ_PRIV, SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
		Set_SPI_Filter_RW_Region("spi_m3", SPI_FILTER_WRITE_PRIV, SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
		SPI_Monitor_Enable("spi_m3", false);
		Set_SPI_Filter_RW_Region("spi_m4", SPI_FILTER_READ_PRIV, SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
		Set_SPI_Filter_RW_Region("spi_m4", SPI_FILTER_WRITE_PRIV, SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
		SPI_Monitor_Enable("spi_m4", false);

		BMCBootRelease();
		PCHBootRelease();
	}

	LOG_DBG("End");
}

void exit_tzero(void *o)
{
	ARG_UNUSED(o);
	LOG_DBG("Start");
	/* Disarm reset monitor */
	platform_monitor_remove();
	LOG_DBG("End");
}

extern struct device *gSwMbxDev;
extern uint8_t gUfmFifoData[64];
extern uint8_t gReadFifoData[64];
extern uint8_t gFifoData;

void handle_provision_event(void *o)
{
	struct event_context *evt_ctx = ((struct smf_context *)o)->event_ctx;

	if ((evt_ctx->data.bit8[1] & EXECUTE_UFM_COMMAND) ||
	    (evt_ctx->data.bit8[1] & FLUSH_WRITE_FIFO) ||
	    (evt_ctx->data.bit8[1] & FLUSH_READ_FIFO)) {
		ClearUfmStatusValue(UFM_CLEAR_ON_NEW_COMMAND);
		// Clear UFM command trigger
		SetUfmCmdTriggerValue(0x00);
		SetUfmStatusValue(COMMAND_BUSY);
		if (evt_ctx->data.bit8[1] & EXECUTE_UFM_COMMAND) {
			LOG_DBG("UFM Trigger Execute");
			process_provision_command();
		} else if (evt_ctx->data.bit8[1] & FLUSH_WRITE_FIFO) {
			LOG_DBG("UFM Flush Write FIFO");
			memset(&gUfmFifoData, 0, sizeof(gUfmFifoData));
			swmbx_flush_fifo(gSwMbxDev, UfmWriteFIFO);
			gFifoData = 0;
		} else if (evt_ctx->data.bit8[1] & FLUSH_READ_FIFO) {
			LOG_DBG("UFM Flush Read FIFO");
			memset(&gReadFifoData, 0, sizeof(gReadFifoData));
			swmbx_flush_fifo(gSwMbxDev, UfmReadFIFO);
			gFifoData = 0;
		}
		ClearUfmStatusValue(COMMAND_BUSY);
		SetUfmStatusValue(COMMAND_DONE);
	}
}

void handle_checkpoint(void *o)
{
	struct event_context *evt_ctx = ((struct smf_context *)o)->event_ctx;

	switch (evt_ctx->data.bit8[0]) {
	case BmcCheckpoint:
		if (evt_ctx->data.bit8[1] == 0x09)
			SetPlatformState(T0_BMC_BOOTED);
		UpdateBmcCheckpoint(evt_ctx->data.bit8[1]);
		break;
	case AcmCheckpoint:
		if (evt_ctx->data.bit8[1] == 0x09)
			SetPlatformState(T0_ACM_BOOTED);
		//UpdateAcmCheckpoint(evt_ctx->data.bit8[1]);
		break;
	case BiosCheckpoint:
		if (evt_ctx->data.bit8[1] == 0x09)
			SetPlatformState(T0_BIOS_BOOTED);
		UpdateBiosCheckpoint(evt_ctx->data.bit8[1]);
		break;
	default:
		break;
	}
}

void handle_update_requested(void *o)
{
	struct smf_context *state = (struct smf_context *)o;
	struct event_context *evt_ctx = state->event_ctx;
	AO_DATA *ao_data_wrap = NULL;
	EVENT_CONTEXT evt_ctx_wrap;
	int ret;
	uint8_t update_region = evt_ctx->data.bit8[1] & 0x3f;
	CPLD_STATUS cpld_update_status;

	LOG_DBG("FIRMWARE_UPDATE Event Data %02x %02x", evt_ctx->data.bit8[0], evt_ctx->data.bit8[1]);

	switch (evt_ctx->data.bit8[0]) {
	case PchUpdateIntent:
		/* CPU/PCH only has access to bit[7:6] and bit[1:0] */
		update_region &= UpdateAtReset | DymanicUpdate | PchRecoveryUpdate | PchActiveUpdate;
		break;
	case BmcUpdateIntent:
		/* BMC has full access */
		if ((update_region & PchActiveUpdate) || (update_region & PchRecoveryUpdate)) {
			ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
			cpld_update_status.BmcToPchStatus = 1;
			ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
		}
		break;
	default:
		break;
	}

	/* Immediate Update */
	uint32_t handled_region = 0;

	while (update_region) {
		uint32_t image_type = 0xFFFFFFFF;

		do {
			/* BMC Active */
			if (update_region & BmcActiveUpdate) {
				SetPlatformState(BMC_FW_UPDATE);
				LOG_INF("BMC Active Firmware Update");
				image_type = BMC_TYPE;
				evt_ctx_wrap.flash = PRIMARY_FLASH_REGION;
				update_region &= ~BmcActiveUpdate;
				handled_region |= BmcActiveUpdate;
				ao_data_wrap = &state->bmc_active_object;
				break;
			}

			/* BMC Recovery */
			if (update_region & BmcRecoveryUpdate) {
				SetPlatformState(BMC_FW_UPDATE);
				LOG_INF("BMC Recovery Firmware Update");
				image_type = BMC_TYPE;
				evt_ctx_wrap.flash = SECONDARY_FLASH_REGION;
				update_region &= ~BmcRecoveryUpdate;
				handled_region |= BmcRecoveryUpdate;
				ao_data_wrap = &state->bmc_active_object;
				break;
			}

			/* PCH Active */
			if (update_region & PchActiveUpdate) {
				SetPlatformState(PCH_FW_UPDATE);
				LOG_INF("PCH Active Firmware Update");
				image_type = PCH_TYPE;
				evt_ctx_wrap.flash = PRIMARY_FLASH_REGION;
				update_region &= ~PchActiveUpdate;
				handled_region |= PchActiveUpdate;
				ao_data_wrap = &state->pch_active_object;
				break;
			}

			/* PCH Recovery */
			if (update_region & PchRecoveryUpdate) {
				SetPlatformState(PCH_FW_UPDATE);
				LOG_INF("PCH Recovery Firmware Update");
				image_type = PCH_TYPE;
				evt_ctx_wrap.flash = SECONDARY_FLASH_REGION;
				update_region &= ~PchRecoveryUpdate;
				handled_region |= PchRecoveryUpdate;
				ao_data_wrap = &state->pch_active_object;
				break;
			}

			/* ROT Active */
			if (update_region & HROTActiveUpdate) {
				SetPlatformState(CPLD_FW_UPDATE);
				LOG_INF("ROT Active Firmware Update");
				image_type = ROT_TYPE;
				update_region &= ~HROTActiveUpdate;
				handled_region |= HROTActiveUpdate;
				break;
			}

			/* ROT Recovery */
			if (update_region & HROTRecoveryUpdate) {
				SetPlatformState(CPLD_FW_UPDATE);
				LOG_INF("ROT Recovery Firmware Update");
				image_type = ROT_TYPE;
				update_region &= ~HROTRecoveryUpdate;
				handled_region |= HROTRecoveryUpdate;
				break;
			}

		} while (0);

		if (image_type != 0xFFFFFFFF)
			ret = update_firmware_image(image_type, ao_data_wrap, &evt_ctx_wrap);

		if (ret != Success) {
			/* TODO: Log failed reason and handle it properly */
			GenerateStateMachineEvent(UPDATE_FAILED, (void *)handled_region);
			break;
		}
	}

	if (update_region == 0 && ret == Success)
		GenerateStateMachineEvent(UPDATE_DONE, (void *)handled_region);
	else
		GenerateStateMachineEvent(UPDATE_FAILED, (void *)handled_region);
}

void do_unprovisioned(void *o)
{
	LOG_DBG("Start");
	struct event_context *evt_ctx = ((struct smf_context *)o)->event_ctx;

	switch (evt_ctx->event) {
	case PROVISION_CMD:
		handle_provision_event(o);
		break;
	default:
		break;
	}

	LOG_DBG("End");
}

void enter_runtime(void *o)
{
	ARG_UNUSED(o);
	LOG_DBG("Start");
#if defined(CONFIG_BMC_CHECKPOINT_RECOVERY)
	AspeedPFR_EnableTimer(BMC_EVENT);
#endif
#if defined(CONFIG_PCH_CHECKPOINT_RECOVERY)
	AspeedPFR_EnableTimer(PCH_EVENT);
#endif
	LOG_DBG("End");
}

void handle_update_at_reset(void *o)
{
	struct smf_context *state = (struct smf_context *)o;
	struct event_context *evt_ctx = state->event_ctx;

	/* Update At Reset save status to UFM */
	CPLD_STATUS cpld_update_status;

	ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
	if (evt_ctx->data.bit8[1] & PchActiveUpdate) {
		cpld_update_status.PchStatus = 1;
		cpld_update_status.Region[2].ActiveRegion = 1;
	}
	if (evt_ctx->data.bit8[1] & PchRecoveryUpdate) {
		cpld_update_status.PchStatus = 1;
		cpld_update_status.Region[2].Recoveryregion = 1;
	}
	if (evt_ctx->data.bit8[1] & HROTActiveUpdate) {
		cpld_update_status.CpldStatus = 1;
		cpld_update_status.CpldRecovery = 1;
		cpld_update_status.Region[0].ActiveRegion = 1;
	}
	if (evt_ctx->data.bit8[1] & BmcActiveUpdate) {
		cpld_update_status.BmcStatus = 1;
		cpld_update_status.Region[1].ActiveRegion = 1;
	}
	if (evt_ctx->data.bit8[1] & BmcRecoveryUpdate) {
		cpld_update_status.BmcStatus = 1;
		cpld_update_status.Region[1].Recoveryregion = 1;
	}
	if (evt_ctx->data.bit8[1] & HROTRecoveryUpdate)
		LOG_ERR("HROTRecoveryUpdate not supported");
	if (evt_ctx->data.bit8[1] & DymanicUpdate)
		LOG_ERR("DymanicUpdate not supported");
	/* Setting updated cpld status to ufm */
	ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
}

void do_runtime(void *o)
{
	LOG_DBG("Start");
	struct event_context *evt_ctx = ((struct smf_context *)o)->event_ctx;

	switch (evt_ctx->event) {
	case PROVISION_CMD:
		handle_provision_event(o);
		break;
	case WDT_CHECKPOINT:
		handle_checkpoint(o);
		break;
	case UPDATE_REQUESTED:
		handle_update_at_reset(o);
		break;
	default:
		break;
	}
	LOG_DBG("End");
}

void do_update(void *o)
{
	LOG_DBG("Start");
	handle_update_requested(o);
	LOG_DBG("End");
}

void enter_lockdown(void *o)
{
	ARG_UNUSED(o);
	LOG_DBG("Start");
	pfr_bmc_srst_enable_ctrl(false);
	BMCBootHold();
	PCHBootHold();
	SetPlatformState(LOCKDOWN_ON_AUTH_FAIL);
	LOG_DBG("End");
}

void do_lockdown(void *o)
{
	ARG_UNUSED(o);
	LOG_DBG("Start");
	LOG_DBG("End");
}

void do_reboot(void *o)
{
	ARG_UNUSED(o);
	LOG_DBG("Start");
	LOG_PANIC();
	pfr_cpld_update_reboot();
	/* Should never reach here? */
	LOG_DBG("End");
}

static const struct smf_state state_table[] = {
	[BOOT] = SMF_CREATE_STATE(NULL, NULL, NULL, NULL),
	[INIT] = SMF_CREATE_STATE(NULL, do_init, NULL, NULL),
	[ROT_RECOVERY] = SMF_CREATE_STATE(NULL, do_rot_recovery, NULL, NULL),
	[TMIN1] = SMF_CREATE_STATE(enter_tmin1, NULL, NULL, NULL),
	[FIRMWARE_VERIFY] = SMF_CREATE_STATE(NULL, do_verify, NULL, &state_table[TMIN1]),
	[FIRMWARE_RECOVERY] = SMF_CREATE_STATE(NULL, do_recovery, NULL, &state_table[TMIN1]),
	[FIRMWARE_UPDATE] = SMF_CREATE_STATE(NULL, do_update, NULL, &state_table[TMIN1]),
	[TZERO] = SMF_CREATE_STATE(enter_tzero, NULL, exit_tzero, NULL),
	[UNPROVISIONED] = SMF_CREATE_STATE(NULL, do_unprovisioned, NULL, &state_table[TZERO]),
	[RUNTIME] = SMF_CREATE_STATE(enter_runtime, do_runtime, NULL, &state_table[TZERO]),
	// [SEAMLESS_UPDATE] = SMF_CREATE_STATE(NULL, do_seamless, NULL, NULL, &state_table[TZERO]),
	[SYSTEM_LOCKDOWN] = SMF_CREATE_STATE(NULL, do_lockdown, NULL, NULL),
	[SYSTEM_REBOOT] = SMF_CREATE_STATE(NULL, do_reboot, NULL, NULL),
};

void AspeedStateMachine(void)
{
	smf_set_initial(SMF_CTX(&s_obj), &state_table[BOOT]);
	GenerateStateMachineEvent(START_STATE_MACHINE, NULL);

	while (1) {
		struct event_context *fifo_in = (struct event_context *)k_fifo_get(&aspeed_sm_fifo, K_FOREVER);

		if (fifo_in == NULL)
			continue;

		s_obj.event_ctx = fifo_in;

		LOG_INF("EVENT IN [%p] EVT=%d DATA=%p", fifo_in, fifo_in->event, fifo_in->data.ptr);
		const struct smf_state *current_state = SMF_CTX(&s_obj)->current;
		const struct smf_state *next_state = NULL;
		bool run_state = false;

		if (current_state == &state_table[BOOT]) {
			switch (fifo_in->event) {
			case START_STATE_MACHINE:
				next_state = &state_table[INIT];
				break;
			default:
				break;
			}
		} else if (current_state == &state_table[INIT]) {
			switch (fifo_in->event) {
			case INIT_DONE:
				next_state = &state_table[FIRMWARE_VERIFY];
				break;
			case INIT_ROT_SECONDARY_BOOTED:
				next_state = &state_table[ROT_RECOVERY];
				break;
			default:
				/* Discard anyother event */
				break;
			}
		} else if (current_state == &state_table[ROT_RECOVERY]) {
			switch (fifo_in->event) {
			case RECOVERY_DONE:
				next_state = &state_table[SYSTEM_REBOOT];
				break;
			case RECOVERY_FAILED:
				next_state = &state_table[SYSTEM_LOCKDOWN];
				break;
			default:
				break;
			}
		} else if (current_state == &state_table[FIRMWARE_VERIFY]) {
			switch (fifo_in->event) {
			case UPDATE_REQUESTED:
				/* Update at reset flag is set */
				next_state = &state_table[FIRMWARE_UPDATE];
				break;
			case VERIFY_UNPROVISIONED:
				next_state = &state_table[UNPROVISIONED];
				break;
			case VERIFY_FAILED:
				next_state = &state_table[FIRMWARE_RECOVERY];
				break;
			case VERIFY_DONE:
				// Firmware is authenticated -> RUNTIME
				// Non provisioned -> UNPROVISIONED
				next_state = &state_table[RUNTIME];
				break;
			case RECOVERY_FAILED:
				/* Recovery -> Verify(BMC Failed) -> Lockdown */
				next_state = &state_table[SYSTEM_LOCKDOWN];
				break;
			default:
				break;
			}
		} else if (current_state == &state_table[FIRMWARE_RECOVERY]) {
			switch (fifo_in->event) {
			case RECOVERY_DONE:
				next_state = &state_table[FIRMWARE_VERIFY];
				break;
			case RECOVERY_FAILED:
				next_state = &state_table[SYSTEM_LOCKDOWN];
				break;
			default:
				break;
			}
		} else if (current_state == &state_table[FIRMWARE_UPDATE]) {
			switch (fifo_in->event) {
			case UPDATE_DONE:
				if (fifo_in->data.bit32 & HROTActiveUpdate) {
					/* Update PFR requires reboot platform */
					next_state = &state_table[SYSTEM_REBOOT];
				} else {
					/* Verify the image then boot */
					next_state = &state_table[FIRMWARE_VERIFY];
				}
				break;
			case UPDATE_FAILED:
				next_state = &state_table[FIRMWARE_VERIFY];
				break;
			default:
				break;
			}
		} else if (current_state == &state_table[RUNTIME]) {
			switch (fifo_in->event) {
			case RESET_DETECTED:
				next_state = &state_table[FIRMWARE_VERIFY];
				break;
			case UPDATE_REQUESTED:
				/* Check update intent, seamless or tmin1 update */
				if (fifo_in->data.bit8[1] & UpdateAtReset) {
					/* Update at reset, just set the status and don't go Tmin1 */
					run_state = true;
				} else {
					/* Immediate update */
					next_state = &state_table[FIRMWARE_UPDATE];
				}
				break;
			case PROVISION_CMD:
			case WDT_CHECKPOINT:
				// Just run provision handling
				run_state = true;
				break;
			case WDT_TIMEOUT:
#if defined(CONFIG_BMC_CHECKPOINT_RECOVERY)
				if (fifo_in->data.bit8[0] == BMC_EVENT)
					next_state = &state_table[FIRMWARE_RECOVERY];
#endif
#if defined(CONFIG_PCH_CHECKPOINT_RECOVERY)
				if (fifo_in->data.bit8[0] == PCH_EVENT)
					next_state = &state_table[FIRMWARE_RECOVERY];
#endif
				break;
			default:
				break;
			}
		} else if (current_state == &state_table[UNPROVISIONED]) {
			switch (fifo_in->event) {
			case PROVISION_CMD:
				// Just run provision handling
				run_state = true;
				break;
			case RESET_DETECTED:
				next_state = &state_table[FIRMWARE_VERIFY];
				break;
			default:
				break;
			}
		}

		if (next_state)
			smf_set_state(SMF_CTX(&s_obj), next_state);

		if (run_state || next_state)
			smf_run_state(SMF_CTX(&s_obj));

		s_obj.event_ctx = NULL;
		k_free(fifo_in);
	}
}

