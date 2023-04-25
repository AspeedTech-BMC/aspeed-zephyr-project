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
#include <drivers/i2c/pfr/i2c_filter.h>
#include <drivers/misc/aspeed/abr_aspeed.h>
#include <drivers/flash.h>

#include "AspeedStateMachine.h"
#include "include/SmbusMailBoxCom.h"
#if defined(CONFIG_INTEL_PFR)
#include "intel_pfr/intel_pfr_definitions.h"
#include "intel_pfr/intel_pfr_provision.h"
#include "intel_pfr/intel_pfr_update.h"
#include "intel_pfr/intel_pfr_verification.h"
#include "intel_pfr/intel_pfr_spi_filtering.h"
#endif
#if defined(CONFIG_CERBERUS_PFR)
#include "cerberus_pfr/cerberus_pfr_definitions.h"
#include "cerberus_pfr/cerberus_pfr_update.h"
#include "cerberus_pfr/cerberus_pfr_spi_filtering.h"
#include "cerberus_pfr/cerberus_pfr_key_manifest.h"
#endif
#include "Smbus_mailbox/Smbus_mailbox.h"
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
#include "watchdog_timer/wdt_utils.h"

#if defined(CONFIG_PFR_MCTP)
#include "mctp/mctp.h"
#endif

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
#include "SPDM/SPDMCommon.h"
#endif

#define MAX_UPD_FAILED_ALLOWED 10

LOG_MODULE_REGISTER(aspeed_state_machine, LOG_LEVEL_DBG);
K_FIFO_DEFINE(aspeed_sm_fifo);
extern uint8_t gWdtBootStatus;

struct smf_context s_obj;
static const struct smf_state state_table[];

enum aspeed_pfr_event event_log[128] = {START_STATE_MACHINE};

enum {
		BmcOnlyReset = 1,
		PchOnlyReset,
};

static uint8_t last_bmc_active_verify_status = Failure;
static uint8_t last_bmc_recovery_verify_status = Failure;
static uint8_t last_pch_active_verify_status = Failure;
static uint8_t last_pch_recovery_verify_status = Failure;

static bool reset_from_unprovision_state = false;

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
	debug_log_init();
	spim_irq_init();

#if 0
	// Halting for JTAG debug
	DEBUG_HALT();
#endif

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

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	state->afm_active_object.type = AFM_EVENT;
	state->afm_active_object.ActiveImageStatus = Failure;
	state->afm_active_object.RecoveryImageStatus = Failure;
	state->afm_active_object.RestrictActiveUpdate = 0;
#endif

	enum boot_indicator rot_boot_from = get_boot_indicator();

	disable_abr_wdt();

	if (rot_boot_from == BOOT_FROM_ALTERNATE_PART) {
		/* ABR secondary booted, copy recovery image to active image */
		LOG_ERR("ROT boot from secondary image, need to recovery ROT active region");
		GenerateStateMachineEvent(INIT_ROT_SECONDARY_BOOTED, NULL);
	} else {
		/* ABR primary booted */
#if defined(CONFIG_PFR_SW_MAILBOX)
		InitializeSmbusMailbox();
#endif
#if defined(CONFIG_PFR_MCTP)
		init_pfr_mctp();
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
		init_spdm();
		/* Read UFM Setting */
		if (IsSpdmAttestationEnabled()) {
			spdm_enable_attester();
			SetProvisionStatus2(0x01);
		} else {
			SetProvisionStatus2(0x00);
		}
#endif
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
	struct event_context *evt_ctx = ((struct smf_context *)o)->event_ctx;
	uint8_t update_region = evt_ctx->data.bit8[1] & PchBmcHROTActiveAndRecoveryUpdate;
	bool bmc_reset_only = false;
	bool pch_reset_only = false;

	LOG_DBG("Start");
	if (evt_ctx->data.bit8[0] == BmcUpdateIntent) {
		LogLastPanic(BMC_UPDATE_INTENT);
		if (!(update_region & ExceptBmcActiveUpdate) &&
				(update_region & BmcActiveUpdate))
			bmc_reset_only = true;
	} else if (evt_ctx->data.bit8[0] == PchUpdateIntent) {
		LogLastPanic(PCH_UPDATE_INTENT);
		if (!(update_region & ExceptPchActiveUpdate) &&
				(update_region & PchActiveUpdate))
			pch_reset_only = true;
	} else if (evt_ctx->event == RESET_DETECTED) {
		LogLastPanic(BMC_RESET_DETECT);
		if (reset_from_unprovision_state) {
			reset_from_unprovision_state = false;
			if (!(GetUfmStatusValue() & UFM_PROVISIONED))
				bmc_reset_only = true;
		} else {
				bmc_reset_only = true;
		}
	}

	if (bmc_reset_only) {
		BMCBootHold();
		evt_ctx->data.bit8[2] = BmcOnlyReset;
		gWdtBootStatus &= ~WDT_BMC_BOOT_DONE_MASK;
	} else if (pch_reset_only) {
		PCHBootHold();
		evt_ctx->data.bit8[2] = PchOnlyReset;
		gWdtBootStatus &= ~WDT_PCH_BOOT_DONE_MASK;
	} else {
		evt_ctx->data.bit8[2] = 0;
		BMCBootHold();
		PCHBootHold();
		gWdtBootStatus &= ~WDT_ALL_BOOT_DONE_MASK;
	}

	SetPlatformState(ENTER_T_MINUS_1);
	LOG_DBG("End");
}

void verify_image(uint32_t image, uint32_t operation, uint32_t flash, struct smf_context *state)
{
	EVENT_CONTEXT evt_wrap;
	int ret;

	evt_wrap.image = image;
	evt_wrap.operation = operation;
	evt_wrap.flash = flash;

	ret = authentication_image(NULL, &evt_wrap);
	if (image == BMC_EVENT) {
		if (operation == VERIFY_ACTIVE) {
			LOG_INF("authentication_image bmc active return %d", ret);
			state->bmc_active_object.ActiveImageStatus = ret ? Failure : Success;
		} else if (operation == VERIFY_BACKUP) {
			LOG_INF("authentication_image bmc backup return %d", ret);
			state->bmc_active_object.RecoveryImageStatus = ret ? Failure : Success;
		}
	} else if (image == PCH_EVENT) {
		if (operation == VERIFY_ACTIVE) {
			LOG_INF("authentication_image host active return %d", ret);
			state->pch_active_object.ActiveImageStatus = ret ? Failure : Success;
		} else if (operation == VERIFY_BACKUP) {
			LOG_INF("authentication_image host backup return %d", ret);
			state->pch_active_object.RecoveryImageStatus = ret ? Failure : Success;
		}
	}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	else if (image == AFM_EVENT) {
		if (operation == VERIFY_ACTIVE) {
			LOG_INF("authentication_image afm active return %d", ret);
			state->afm_active_object.ActiveImageStatus = ret ? Failure : Success;
		} else if (operation == VERIFY_BACKUP) {
			LOG_INF("authentication_image afm backup return %d", ret);
			state->afm_active_object.RecoveryImageStatus = ret ? Failure : Success;
		}
	}
#endif
}

#if defined(CONFIG_PIT_PROTECTION)
void handle_pit_event(void *o)
{
	uint8_t provision_state = GetUfmStatusValue();
	uint32_t UfmStatus;

	if (!(provision_state & UFM_PROVISIONED))
		return;

	get_provision_data_in_flash(UFM_STATUS, (uint8_t *)&UfmStatus, sizeof(UfmStatus));

	if (CheckUfmStatus(UfmStatus, UFM_STATUS_PIT_HASH_STORED_BIT_MASK) ||
			CheckUfmStatus(UfmStatus, UFM_STATUS_PIT_L2_PASSED_BIT_MASK))
		return;

	if (CheckUfmStatus(UfmStatus, UFM_STATUS_PIT_L2_ENABLE_BIT_MASK))
		GenerateStateMachineEvent(SEAL_FIRMWARE, NULL);
}

int handle_pit_verification(void *o)
{
	byte provision_state = GetUfmStatusValue();

	if (!(provision_state & UFM_PROVISIONED)) {
		// Unprovisioned, populate INIT_UNPROVISIONED event will enter UNPROVISIONED state
		GenerateStateMachineEvent(VERIFY_UNPROVISIONED, NULL);
		return Failure;
	} else {
		if (intel_pfr_pit_level1_verify()) {
			// lockdown
			GenerateStateMachineEvent(RECOVERY_FAILED, NULL);
			return Failure;
		}
		if (intel_pfr_pit_level2_verify()) {
			// lockdown
			GenerateStateMachineEvent(RECOVERY_FAILED, NULL);
			return Failure;
		}
	}

	return Success;
}
#endif

#if defined(CONFIG_CERBERUS_PFR)
int handle_key_manifest_verification(void *o)
{
	struct pfr_manifest *pfr_manifest = get_pfr_manifest();
	byte provision_state = GetUfmStatusValue();

	if (!(provision_state & UFM_PROVISIONED)) {
		// Unprovisioned, populate INIT_UNPROVISIONED event will enter UNPROVISIONED state
		GenerateStateMachineEvent(VERIFY_UNPROVISIONED, NULL);
		return Failure;
	} else {
		if (cerberus_pfr_verify_all_key_manifests(pfr_manifest)) {
			// lockdown
			GenerateStateMachineEvent(RECOVERY_FAILED, NULL);
			return Failure;
		}
	}

	return Success;
}
#endif

void handle_image_verification(void *o)
{
	struct smf_context *state = (struct smf_context *)o;
	struct event_context *evt_ctx = ((struct smf_context *)o)->event_ctx;

	byte provision_state = GetUfmStatusValue();

	if (!(provision_state & UFM_PROVISIONED)) {
		// Unprovisioned, populate INIT_UNPROVISIONED event will enter UNPROVISIONED state
		GenerateStateMachineEvent(VERIFY_UNPROVISIONED, evt_ctx->data.ptr);
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
				data.bit8[2] = evt_ctx->data.bit8[2];
				data.bit8[3] = evt_ctx->data.bit8[3];
				GenerateStateMachineEvent(UPDATE_REQUESTED, data.ptr);
			}
		}

		/* No pending update, verify images */
		if (update_reset == false) {
			if (evt_ctx->data.bit8[2] == BmcOnlyReset) {
				verify_image(BMC_EVENT, VERIFY_BACKUP, SECONDARY_FLASH_REGION, state);
				verify_image(BMC_EVENT, VERIFY_ACTIVE, PRIMARY_FLASH_REGION, state);
				state->pch_active_object.ActiveImageStatus =
					last_pch_active_verify_status;
				state->pch_active_object.RecoveryImageStatus =
					last_pch_recovery_verify_status;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
				verify_image(AFM_EVENT, VERIFY_ACTIVE, PRIMARY_FLASH_REGION, state);
#endif
			} else if (evt_ctx->data.bit8[2] == PchOnlyReset) {
				verify_image(PCH_EVENT, VERIFY_BACKUP, SECONDARY_FLASH_REGION, state);
				verify_image(PCH_EVENT, VERIFY_ACTIVE, PRIMARY_FLASH_REGION, state);
				state->bmc_active_object.ActiveImageStatus =
					last_bmc_active_verify_status;
				state->bmc_active_object.RecoveryImageStatus =
					last_bmc_recovery_verify_status;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
				verify_image(AFM_EVENT, VERIFY_ACTIVE, PRIMARY_FLASH_REGION, state);
#endif
			} else {
				/* BMC Verification */
				SetPlatformState(BMC_FLASH_AUTH);
				verify_image(BMC_EVENT, VERIFY_BACKUP, SECONDARY_FLASH_REGION, state);
				verify_image(BMC_EVENT, VERIFY_ACTIVE, PRIMARY_FLASH_REGION, state);

				/* PCH Verification */
				SetPlatformState(PCH_FLASH_AUTH);
				verify_image(PCH_EVENT, VERIFY_BACKUP, SECONDARY_FLASH_REGION, state);
				verify_image(PCH_EVENT, VERIFY_ACTIVE, PRIMARY_FLASH_REGION, state);

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
				// SetPlatformState(AFM_FLASH_AUTH); // Not defined in documented
				verify_image(AFM_EVENT, VERIFY_BACKUP, SECONDARY_FLASH_REGION, state);
				verify_image(AFM_EVENT, VERIFY_ACTIVE, PRIMARY_FLASH_REGION, state);
#endif
			}


			/* Success = 0, Failure = 1 */
			if (state->bmc_active_object.ActiveImageStatus) {
				if (state->bmc_active_object.RecoveryImageStatus)
					LogErrorCodes(BMC_AUTH_FAIL, ACTIVE_RECOVERY_AUTH_FAIL);
				else
					LogErrorCodes(BMC_AUTH_FAIL, ACTIVE_AUTH_FAIL);
			} else if (state->bmc_active_object.RecoveryImageStatus) {
				LogErrorCodes(BMC_AUTH_FAIL, RECOVERY_AUTH_FAIL);
			}

			if (state->pch_active_object.ActiveImageStatus) {
				if (state->pch_active_object.RecoveryImageStatus)
					LogErrorCodes(PCH_AUTH_FAIL, ACTIVE_RECOVERY_AUTH_FAIL);
				else
					LogErrorCodes(PCH_AUTH_FAIL, ACTIVE_AUTH_FAIL);
			} else if (state->pch_active_object.RecoveryImageStatus) {
				LogErrorCodes(PCH_AUTH_FAIL, RECOVERY_AUTH_FAIL);
			}

			if (state->bmc_active_object.ActiveImageStatus || !state->bmc_active_object.RecoveryImageStatus)
				state->bmc_active_object.RestrictActiveUpdate = 0;

			if (state->pch_active_object.ActiveImageStatus || !state->pch_active_object.RecoveryImageStatus)
				state->pch_active_object.RestrictActiveUpdate = 0;

			LOG_INF("BMC image verification recovery=%s active=%s",
					state->bmc_active_object.RecoveryImageStatus ? "Bad" : "Good",
					state->bmc_active_object.ActiveImageStatus ? "Bad" : "Good");
			last_bmc_recovery_verify_status = state->bmc_active_object.RecoveryImageStatus;
			last_bmc_active_verify_status = state->bmc_active_object.ActiveImageStatus;
			if (state->bmc_active_object.RestrictActiveUpdate)
				LOG_WRN("BMC Restrict Active Update Mode");

			LOG_INF("PCH image verification recovery=%s active=%s",
					state->pch_active_object.RecoveryImageStatus ? "Bad" : "Good",
					state->pch_active_object.ActiveImageStatus ? "Bad" : "Good");
			last_pch_recovery_verify_status = state->pch_active_object.RecoveryImageStatus;
			last_pch_active_verify_status = state->pch_active_object.ActiveImageStatus;
			if (state->pch_active_object.RestrictActiveUpdate)
				LOG_WRN("PCH Restrict Active Update Mode");

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
			if (state->afm_active_object.ActiveImageStatus || !state->afm_active_object.RecoveryImageStatus)
				state->afm_active_object.RestrictActiveUpdate = 0;

			LOG_INF("AFM image verification recovery=%s active=%s",
					state->afm_active_object.RecoveryImageStatus ? "Bad" : "Good",
					state->afm_active_object.ActiveImageStatus ? "Bad" : "Good");
			if (state->afm_active_object.RestrictActiveUpdate)
				LOG_WRN("AFM Restrict Active Update Mode");
#endif


			if (evt_ctx->event != RECOVERY_DONE) {
				if (state->pch_active_object.ActiveImageStatus == Failure
						|| state->bmc_active_object.ActiveImageStatus == Failure
						|| state->pch_active_object.RecoveryImageStatus == Failure
						|| state->bmc_active_object.RecoveryImageStatus == Failure
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
						|| state->afm_active_object.ActiveImageStatus == Failure
						|| state->afm_active_object.RecoveryImageStatus == Failure
#endif
						) {
					/* ACT/RCV region went wrong, go recovery */
					GenerateStateMachineEvent(VERIFY_FAILED, evt_ctx->data.ptr);
				} else {
					/* Everything good, done */
					GenerateStateMachineEvent(VERIFY_DONE, evt_ctx->data.ptr);
				}
			} else {
				/* Coming back from RECOVERY, relax some condition */
				if (state->bmc_active_object.ActiveImageStatus == Success) {
					/* If BMC is good to go, just boot the BMC. It wiil be checked by Tzero */
					GenerateStateMachineEvent(VERIFY_DONE, evt_ctx->data.ptr);
				} else {
					/* SYSTEM LOCKDOWN */
					GenerateStateMachineEvent(RECOVERY_FAILED, evt_ctx->data.ptr);
				}
			}
		}
	}
}

void do_verify(void *o)
{
	LOG_DBG("Start");
#if defined(CONFIG_PIT_PROTECTION)
	if (handle_pit_verification(o))
		goto exit;
#endif
#if defined(CONFIG_CERBERUS_PFR)
	if (handle_key_manifest_verification(o))
		goto exit;
#endif
	handle_image_verification(o);
exit:
	LOG_DBG("End");
}

void handle_recovery(void *o)
{
	struct smf_context *state = (struct smf_context *)o;
	struct event_context *evt_ctx = state->event_ctx;
	union aspeed_event_data data;

	/* Check Staging Image */
	bool recovery_done = 0;
	int ret;
	EVENT_CONTEXT evt_wrap;

	initializeEngines();
	initializeManifestProcessor();
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
			LogRecovery(BMC_RECOVERY_FAIL);
			evt_wrap.image = BMC_EVENT;
			ret = recover_image(&state->bmc_active_object, &evt_wrap);

			LOG_INF("BMC recover recovery region return=%d", ret);
			if (ret == Success || ret == VerifyActive || ret == VerifyRecovery)
				recovery_done = 1;
		}

		if (state->bmc_active_object.ActiveImageStatus == Failure) {
			if (evt_ctx->event != WDT_TIMEOUT)
				LogRecovery(BMC_ACTIVE_FAIL);
			evt_wrap.image = BMC_EVENT;
			ret = recover_image(&state->bmc_active_object, &evt_wrap);
			LOG_INF("BMC recover active region return=%d", ret);
			if (ret == Success || ret == VerifyActive || ret == VerifyRecovery)
				recovery_done = 1;
#if defined(CONFIG_BMC_CHECKPOINT_RECOVERY) && defined(CONFIG_INTEL_PFR)
			if (evt_ctx->event == WDT_TIMEOUT)
				inc_recovery_level(BMC_SPI);
#endif

		}

		if (state->pch_active_object.RecoveryImageStatus == Failure) {
			LogRecovery(PCH_RECOVERY_FAIL);
			evt_wrap.image = PCH_EVENT;
			ret = recover_image(&state->pch_active_object, &evt_wrap);
			LOG_INF("PCH Recovery return=%d", ret);
			recovery_done = 1;
		}

		if (state->pch_active_object.ActiveImageStatus == Failure) {
			if (evt_ctx->event != WDT_TIMEOUT)
				LogRecovery(PCH_ACTIVE_FAIL);
			evt_wrap.image = PCH_EVENT;
			ret = recover_image(&state->pch_active_object, &evt_wrap);
			LOG_INF("PCH Recovery return=%d", ret);
			recovery_done = 1;
#if defined(CONFIG_PCH_CHECKPOINT_RECOVERY) && defined(CONFIG_INTEL_PFR)
			if (evt_ctx->event == WDT_TIMEOUT)
				inc_recovery_level(PCH_SPI);
#endif
		}

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
		if (state->afm_active_object.RecoveryImageStatus == Failure) {
			// LogRecovery(AFM_RECOVERY_FAIL);
			evt_wrap.image = AFM_EVENT;
			ret = recover_image(&state->afm_active_object, &evt_wrap);
			recovery_done = 1;
		}

		if (state->afm_active_object.ActiveImageStatus == Failure) {
			// LogRecovery(AFM_ACTIVE_FAIL);
			evt_wrap.image = AFM_EVENT;
			ret = recover_image(&state->afm_active_object, &evt_wrap);
			LOG_INF("AFM Recovery return=%d", ret);
			/* Even if AFM recovery failed, the BMC/PCH are still allow to boot,
			 * but the attestation service will be disabled. */
			recovery_done = 1;
		}
#endif
		break;
	default:
		break;
	}

	data.bit8[2] = evt_ctx->data.bit8[2];

	if (recovery_done)
		GenerateStateMachineEvent(RECOVERY_DONE, data.ptr);
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
	struct event_context *evt_ctx = ((struct smf_context *)o)->event_ctx;

	/* Arm reset monitor */
	bmc_reset_monitor_init();
	platform_monitor_init();
	if (state->ctx.current == &state_table[RUNTIME]) {
		if (evt_ctx->data.bit8[2] == BmcOnlyReset) {
			apply_pfm_protection(BMC_SPI);
#if defined(CONFIG_CERBERUS_PFR)
			apply_pfm_smbus_protection(BMC_SPI);
#endif
			BMCBootRelease();
			goto enter_tzero_end;
		} else if (evt_ctx->data.bit8[2] == PchOnlyReset) {
			apply_pfm_protection(PCH_SPI);
#if defined(CONFIG_CERBERUS_PFR)
			apply_pfm_smbus_protection(PCH_SPI);
#endif
			PCHBootRelease();
			goto enter_tzero_end;
		}
		/* Provisioned */
		/* Releasing System Reset */
		if (state->bmc_active_object.ActiveImageStatus == Success) {
			/* Arm SPI/I2C Filter */
			apply_pfm_protection(BMC_SPI);
#if defined(CONFIG_CERBERUS_PFR)
			apply_pfm_smbus_protection(BMC_SPI);
#endif
			BMCBootRelease();
		} else {
			/* Should not enter here, redirect to LOCKDOWN */
			LOG_ERR("BMC firmware is invalid, lockdown the platform");
		}

		if (state->pch_active_object.ActiveImageStatus == Success) {
			/* Arm SPI/I2C Filter */
			apply_pfm_protection(PCH_SPI);
#if defined(CONFIG_CERBERUS_PFR)
			apply_pfm_smbus_protection(PCH_SPI);
#endif
			PCHBootRelease();
		} else
			LOG_ERR("Host firmware is invalid, host won't boot");
	} else {
		/* Unprovisioned - Releasing System Reset */
		if (device_get_binding("spi_m1") != NULL) {
			Set_SPI_Filter_RW_Region("spi_m1", SPI_FILTER_READ_PRIV,
					SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
			Set_SPI_Filter_RW_Region("spi_m1", SPI_FILTER_WRITE_PRIV,
					SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
			SPI_Monitor_Enable("spi_m1", false);
			LOG_INF("Bypass %s", "spi_m1");
		}

		if (device_get_binding("spi_m2") != NULL) {
			Set_SPI_Filter_RW_Region("spi_m2", SPI_FILTER_READ_PRIV,
					SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
			Set_SPI_Filter_RW_Region("spi_m2", SPI_FILTER_WRITE_PRIV,
					SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
			SPI_Monitor_Enable("spi_m2", false);
			LOG_INF("Bypass %s", "spi_m2");
		}

		if (device_get_binding("spi_m3") != NULL) {
			Set_SPI_Filter_RW_Region("spi_m3", SPI_FILTER_READ_PRIV,
					SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
			Set_SPI_Filter_RW_Region("spi_m3", SPI_FILTER_WRITE_PRIV,
					SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
			SPI_Monitor_Enable("spi_m3", false);
			LOG_INF("Bypass %s", "spi_m3");
		}

		if (device_get_binding("spi_m4") != NULL) {
			Set_SPI_Filter_RW_Region("spi_m4", SPI_FILTER_READ_PRIV,
					SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
			Set_SPI_Filter_RW_Region("spi_m4", SPI_FILTER_WRITE_PRIV,
					SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
			SPI_Monitor_Enable("spi_m4", false);
			LOG_INF("Bypass %s", "spi_m4");
		}

		/* Releasing I2C Filter */
		const struct device *dev = NULL;
		if ((dev = device_get_binding("I2C_FILTER_0")) != NULL) {
			ast_i2c_filter_init(dev);
			ast_i2c_filter_en(dev, true, false, false, false);
			LOG_INF("Bypass %s", dev->name);
		}

		if ((dev = device_get_binding("I2C_FILTER_1")) != NULL) {
			ast_i2c_filter_init(dev);
			ast_i2c_filter_en(dev, true, false, false, false);
			LOG_INF("Bypass %s", dev->name);
		}

		if ((dev = device_get_binding("I2C_FILTER_2")) != NULL) {
			ast_i2c_filter_init(dev);
			ast_i2c_filter_en(dev, true, false, false, false);
			LOG_INF("Bypass %s", dev->name);
		}

		if ((dev = device_get_binding("I2C_FILTER_3")) != NULL) {
			ast_i2c_filter_init(dev);
			ast_i2c_filter_en(dev, true, false, false, false);
			LOG_INF("Bypass %s", dev->name);
		}

		if ((dev = device_get_binding("I2C_FILTER_4")) != NULL) {
			ast_i2c_filter_init(dev);
			ast_i2c_filter_en(dev, true, false, false, false);
			LOG_INF("Bypass %s", dev->name);
		}

		if (evt_ctx->data.bit8[2] == BmcOnlyReset) {
			BMCBootRelease();
		} else if (evt_ctx->data.bit8[2] == PchOnlyReset) {
			PCHBootRelease();
		} else {
			BMCBootRelease();
			PCHBootRelease();
		}
	}

enter_tzero_end:
	LOG_DBG("End");
}

void exit_tzero(void *o)
{
	ARG_UNUSED(o);
	LOG_DBG("Start");
	/* Disarm reset monitor */
	bmc_reset_monitor_remove();
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

#if defined(CONFIG_CERBERUS_PFR)
void handle_provision_image(void *o)
{
	LOG_INF("Handle Provision Image");
	AO_DATA *ao_data_wrap = NULL;
	EVENT_CONTEXT evt_ctx_wrap;
	uint32_t image_type = ROT_TYPE;
	int ret;

	const struct device *dev_m = device_get_binding(BMC_SPI_MONITOR);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);
#if defined(CONFIG_DUAL_FLASH)
	dev_m = device_get_binding(BMC_SPI_MONITOR_2);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);
#endif
	ret = update_firmware_image(image_type, ao_data_wrap, &evt_ctx_wrap);
	dev_m = device_get_binding(BMC_SPI_MONITOR);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
#if defined(CONFIG_DUAL_FLASH)
	dev_m = device_get_binding(BMC_SPI_MONITOR_2);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
#endif

	LOG_INF("Provision result = %d", ret);
}
#endif

void handle_checkpoint(void *o)
{
	struct smf_context *state = (struct smf_context *)o;
	struct event_context *evt_ctx = ((struct smf_context *)o)->event_ctx;

	switch (evt_ctx->data.bit8[0]) {
	case BmcCheckpoint:
		UpdateBmcCheckpoint(evt_ctx->data.bit8[1]);
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
		if (state->afm_active_object.ActiveImageStatus == Success) {
			spdm_run_attester();
		}
#endif
		break;
#if defined(CONFIG_INTEL_PFR)
	case AcmCheckpoint:
		UpdateAcmCheckpoint(evt_ctx->data.bit8[1]);
		break;
#endif
	case BiosCheckpoint:
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
	int ret = Success;
	uint8_t update_region = evt_ctx->data.bit8[1] & PchBmcHROTActiveAndRecoveryUpdate;
	CPLD_STATUS cpld_update_status;


	LOG_DBG("FIRMWARE_UPDATE Event Data %02x %02x", evt_ctx->data.bit8[0], evt_ctx->data.bit8[1]);

	switch (evt_ctx->data.bit8[0]) {
	case PchUpdateIntent:
		/* CPU/PCH only has access to bit[7:6] and bit[1:0] */
		update_region &= UpdateAtReset | DymanicUpdate | PchRecoveryUpdate | PchActiveUpdate;
		if (!update_region)
			LogUpdateFailure(INVALID_UPD_INTENT, 0);
		break;
	case BmcUpdateIntent:
		/* BMC has full access */
		if ((update_region & PchActiveUpdate) || (update_region & PchRecoveryUpdate)) {
			ufm_read(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
			cpld_update_status.BmcToPchStatus = 1;
			ufm_write(UPDATE_STATUS_UFM, UPDATE_STATUS_ADDRESS, (uint8_t *)&cpld_update_status, sizeof(CPLD_STATUS));
		}
		break;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	case BmcUpdateIntent2:
		if (evt_ctx->data.bit8[1] & AfmActiveAndRecoveryUpdate) {
			update_region &= AfmActiveAndRecoveryUpdate;
		}
		break;
#endif
	default:
		break;
	}

	/* Immediate Update */
	uint8_t handled_region = 0;

	while (update_region) {
		uint32_t image_type = 0xFFFFFFFF;

		do {
			if (evt_ctx->data.bit8[0] == PchUpdateIntent || evt_ctx->data.bit8[0] == BmcUpdateIntent) {
				/* BMC Active */
				if (update_region & BmcActiveUpdate) {
					SetPlatformState(BMC_FW_UPDATE);
					LOG_INF("BMC Active Firmware Update");
					image_type = BMC_TYPE;
					evt_ctx_wrap.flag = evt_ctx->data.bit8[1] & UPDATE_DYNAMIC;
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
					evt_ctx_wrap.flag = evt_ctx->data.bit8[1] & UPDATE_DYNAMIC;
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
					evt_ctx_wrap.flag = evt_ctx->data.bit8[1] & UPDATE_DYNAMIC;
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
					evt_ctx_wrap.flag = evt_ctx->data.bit8[1] & UPDATE_DYNAMIC;
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
			}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
			else if (evt_ctx->data.bit8[0] == BmcUpdateIntent2) {
				if (update_region & AfmActiveUpdate) {
					LOG_INF("AFM Active Firmware Update");
					image_type = AFM_TYPE;
					evt_ctx_wrap.flash = PRIMARY_FLASH_REGION;
					update_region &= ~AfmActiveUpdate;
					handled_region |= AfmActiveUpdate;
					ao_data_wrap = &state->afm_active_object;
					break;
				}

				if (update_region & AfmRecoveryUpdate) {
					LOG_INF("AFM Recovery Firmware Update");
					image_type = AFM_TYPE;
					evt_ctx_wrap.flash = SECONDARY_FLASH_REGION;
					update_region &= ~AfmRecoveryUpdate;
					handled_region |= AfmRecoveryUpdate;
					ao_data_wrap = &state->afm_active_object;
					break;
				}
			}
#endif
			else {
				LOG_ERR("Unsupported update intent");
			}
		} while (0);

		if (image_type != 0xFFFFFFFF)
			ret = update_firmware_image(image_type, ao_data_wrap, &evt_ctx_wrap);

		evt_ctx->data.bit8[3] = handled_region;

		if (ret != Success) {
			/* TODO: Log failed reason and handle it properly */
			GenerateStateMachineEvent(UPDATE_FAILED, evt_ctx->data.ptr);
			break;
		}
	}

	if (update_region == 0 && ret == Success)
		GenerateStateMachineEvent(UPDATE_DONE, evt_ctx->data.ptr);
	else
		GenerateStateMachineEvent(UPDATE_FAILED, evt_ctx->data.ptr);
}

#if defined(CONFIG_SEAMLESS_UPDATE)
void handle_seamless_update_requested(void *o)
{
	struct smf_context *state = (struct smf_context *)o;
	struct event_context *evt_ctx = state->event_ctx;
	AO_DATA *ao_data_wrap = NULL;
	EVENT_CONTEXT evt_ctx_wrap;
	int ret;
	uint8_t update_region = evt_ctx->data.bit8[1] & 0x3f;
	CPLD_STATUS cpld_update_status;

	evt_ctx_wrap.operation = NONE;
	LOG_DBG("SEAMLESS_UPDATE Event Data %02x %02x", evt_ctx->data.bit8[0], evt_ctx->data.bit8[1]);

	switch (evt_ctx->data.bit8[0]) {
		case PchUpdateIntent2:
			if (evt_ctx->data.bit8[1] & BIT(0))
				update_region &= SeamlessUpdate;
			break;
		case BmcUpdateIntent2:
			if (evt_ctx->data.bit8[1] & BIT(0)) {
				update_region &= SeamlessUpdate;
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
			/* PCH Seamless */
			if (update_region & SeamlessUpdate) {
				LOG_INF("PCH Seamless Update");
				evt_ctx_wrap.operation = SEAMLESS_UPDATE_OP;
				SetPlatformState(PCH_SEAMLESS_UPDATE);
				image_type = PCH_TYPE;
				update_region &= ~SeamlessUpdate;
				handled_region |= SeamlessUpdate;
				break;
			}
		} while (0);

		if (evt_ctx_wrap.operation == SEAMLESS_UPDATE_OP) {
			ret = perform_seamless_update(image_type, ao_data_wrap, &evt_ctx_wrap);
			SetPlatformState(PCH_SEAMLESS_UPDATE_DONE);
			if (ret != Success)
				GenerateStateMachineEvent(SEAMLESS_UPDATE_FAILED, (void *)handled_region);
			else
				GenerateStateMachineEvent(SEAMLESS_UPDATE_DONE, (void *)handled_region);
		}
	}
}

void handle_seamless_update_verification(void *o)
{
	const struct device *dev_m = NULL;
	int ret;

	EVENT_CONTEXT evt_wrap;

	evt_wrap.image = PCH_EVENT;
	evt_wrap.operation = VERIFY_ACTIVE;
	evt_wrap.flash = PRIMARY_FLASH_REGION;

	LOG_INF("Switch PCH SPI MUX to ROT");
	dev_m = device_get_binding(PCH_SPI_MONITOR);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);
#if defined(CONFIG_DUAL_FLASH)
	dev_m = device_get_binding(PCH_SPI_MONITOR_2);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_ROT);
#endif

	ret = authentication_image(NULL, &evt_wrap);


	LOG_INF("authentication_image host active return %d", ret);

	if (ret == 0) {
		LOG_INF("Applying PCH SPI Region protection");
		apply_pfm_protection(PCH_SPI);
		GenerateStateMachineEvent(SEAMLESS_VERIFY_DONE, NULL);
	}
	else {
		LogUpdateFailure(SEAMLESS_AUTH_FAILED_AFTER_UPDATE, 0);
		GenerateStateMachineEvent(SEAMLESS_VERIFY_FAILED, NULL);
	}

	LOG_INF("Switch PCH SPI MUX to PCH");
	dev_m = device_get_binding(PCH_SPI_MONITOR);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
#if defined(CONFIG_DUAL_FLASH)
	dev_m = device_get_binding(PCH_SPI_MONITOR_2);
	spim_ext_mux_config(dev_m, SPIM_EXT_MUX_BMC_PCH);
#endif
}
#endif

void do_unprovisioned(void *o)
{
	LOG_DBG("Start");
	struct event_context *evt_ctx = ((struct smf_context *)o)->event_ctx;

	switch (evt_ctx->event) {
#if defined(CONFIG_CERBERUS_PFR)
	case UPDATE_REQUESTED:
		handle_provision_image(o);
		break;
#endif
	case PROVISION_CMD:
		handle_provision_event(o);
#if defined(CONFIG_PIT_PROTECTION)
		handle_pit_event(o);
#endif
		break;
	default:
		break;
	}

	LOG_DBG("End");
}

void enter_runtime(void *o)
{
	LOG_DBG("Start");
	struct event_context *evt_ctx = ((struct smf_context *)o)->event_ctx;
	switch (evt_ctx->event) {
#if defined(CONFIG_SEAMLESS_UPDATE)
		case SEAMLESS_UPDATE_DONE:
		case SEAMLESS_UPDATE_FAILED:
		case SEAMLESS_VERIFY_DONE:
		case SEAMLESS_VERIFY_FAILED:
			break;
#endif
		default:
			if (evt_ctx->data.bit8[2] == BmcOnlyReset) {
#if defined(CONFIG_BMC_CHECKPOINT_RECOVERY)
				pfr_start_timer(BMC_TIMER, WDT_BMC_TIMER_MAXTIMEOUT);
#endif
			} else if (evt_ctx->data.bit8[2] == PchOnlyReset) {
#if defined(CONFIG_PCH_CHECKPOINT_RECOVERY)
#if defined(CONFIG_INTEL_PFR)
#ifdef SUPPORT_ME
				pfr_start_timer(ME_TIMER, WDT_ME_TIMER_MAXTIMEOUT);
#else
				pfr_start_timer(ACM_TIMER, WDT_BIOS_TIMER_MAXTIMEOUT);
#endif
#else
				pfr_start_timer(BIOS_TIMER, WDT_BIOS_TIMER_MAXTIMEOUT);
#endif
#endif
			} else {
#if defined(CONFIG_BMC_CHECKPOINT_RECOVERY)
				pfr_start_timer(BMC_TIMER, WDT_BMC_TIMER_MAXTIMEOUT);
#endif
#if defined(CONFIG_PCH_CHECKPOINT_RECOVERY)
#if defined(CONFIG_INTEL_PFR)
#ifdef SUPPORT_ME
				pfr_start_timer(ME_TIMER, WDT_ME_TIMER_MAXTIMEOUT);
#else
				pfr_start_timer(ACM_TIMER, WDT_BIOS_TIMER_MAXTIMEOUT);
#endif
#else
				pfr_start_timer(BIOS_TIMER, WDT_BIOS_TIMER_MAXTIMEOUT);
#endif
#endif
			}
			break;
	}

	LOG_DBG("End");
}

void exit_runtime(void *o)
{
	LOG_DBG("Start");

#if defined(CONFIG_PFR_SPDM_ATTESTATION)
	spdm_stop_attester();
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
#if defined(CONFIG_PIT_PROTECTION)
		handle_pit_event(o);
#endif
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

#if defined(CONFIG_SEAMLESS_UPDATE)
void do_seamless_update(void *o)
{
	LOG_DBG("Start");
	handle_seamless_update_requested(o);
	LOG_DBG("End");
}

void do_seamless_verify(void *o)
{
	LOG_DBG("Start");
	handle_seamless_update_verification(o);
	LOG_DBG("End");
}
#endif

void enter_lockdown(void *o)
{
	ARG_UNUSED(o);
	LOG_DBG("Start");
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
	[RUNTIME] = SMF_CREATE_STATE(enter_runtime, do_runtime, exit_runtime, &state_table[TZERO]),
#if defined(CONFIG_SEAMLESS_UPDATE)
	[SEAMLESS_UPDATE] = SMF_CREATE_STATE(NULL, do_seamless_update, NULL, &state_table[TZERO]),
	[SEAMLESS_VERIFY] = SMF_CREATE_STATE(NULL, do_seamless_verify, NULL, &state_table[TZERO]),
#endif
	[SYSTEM_LOCKDOWN] = SMF_CREATE_STATE(NULL, do_lockdown, NULL, &state_table[TMIN1]),
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
				ClearUpdateFailure();

				if (fifo_in->data.bit8[0] == BmcUpdateIntent && fifo_in->data.bit8[3] & HROTActiveUpdate) {
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
#if defined(CONFIG_PIT_PROTECTION)
			case SEAL_FIRMWARE:
#endif
				next_state = &state_table[FIRMWARE_VERIFY];
				break;
			case UPDATE_REQUESTED:
				if (getFailedUpdateAttemptsCount() >= MAX_UPD_FAILED_ALLOWED) {
					LogUpdateFailure(UPD_EXCEED_MAX_FAIL_ATTEMPT, 0);
					break;
				}
				/* Check update intent, seamless or tmin1 update */
				if (fifo_in->data.bit8[1] & PchBmcHROTActiveAndRecoveryUpdate) {
					if (fifo_in->data.bit8[1] & UpdateAtReset) {
						/* Update at reset, just set the status and don't go Tmin1 */
						run_state = true;
					} else {
						/* Immediate update */
						next_state = &state_table[FIRMWARE_UPDATE];
					}
				} else {
					/* Discard the request */
					LOG_ERR("UPDATE_INTENT %02x without any target (PCH/BMC/PFR), skipped",
							fifo_in->data.bit8[1]);
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
			case UPDATE_INTENT_2_REQUESTED:
				if (getFailedUpdateAttemptsCount() >= MAX_UPD_FAILED_ALLOWED) {
					LogUpdateFailure(UPD_EXCEED_MAX_FAIL_ATTEMPT, 0);
					break;
				}
				if (fifo_in->data.bit8[1] & AfmActiveAndRecoveryUpdate ||
				    fifo_in->data.bit8[1] & CPLDUpdate)
					next_state = &state_table[FIRMWARE_UPDATE];
#if defined(CONFIG_SEAMLESS_UPDATE)
				else if (fifo_in->data.bit8[1] & SeamlessUpdate)
					next_state = &state_table[SEAMLESS_UPDATE];
#endif
				break;
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
			case ATTESTATION_FAILED:
				next_state = &state_table[SYSTEM_LOCKDOWN];
				break;
#endif
			default:
				break;
			}
		} else if (current_state == &state_table[UNPROVISIONED]) {
			switch (fifo_in->event) {
			case PROVISION_CMD:
				// Just run provision handling
				run_state = true;
				break;
#if defined(CONFIG_CERBERUS_PFR)
			case UPDATE_REQUESTED:
				// Only accept for provisioning capsule
				if (fifo_in->data.bit8[1] & HROTActiveUpdate) {
					run_state = true;
					// next_state = &state_table[FIRMWARE_UPDATE];
				}
				break;
#endif
			case RESET_DETECTED:
				reset_from_unprovision_state = true;
#if defined(CONFIG_PIT_PROTECTION)
			case SEAL_FIRMWARE:
#endif
				next_state = &state_table[FIRMWARE_VERIFY];
				break;
			default:
				break;
			}
		}
#if defined(CONFIG_SEAMLESS_UPDATE)
		else if (current_state == &state_table[SEAMLESS_UPDATE]) {
			switch (fifo_in->event) {
				case SEAMLESS_UPDATE_DONE:
					ClearUpdateFailure();
					next_state = &state_table[SEAMLESS_VERIFY];
					break;
				case SEAMLESS_UPDATE_FAILED:
					// Skip verification, firmware will be recovered in
					// the next bootup.
					LogUpdateFailure(UPD_CAPSULE_AUTH_FAIL, 1);
					next_state = &state_table[RUNTIME];
					break;
				default:
					break;
			}

		} else if (current_state == &state_table[SEAMLESS_VERIFY]) {
			next_state = &state_table[RUNTIME];
			switch (fifo_in->event) {
				case SEAMLESS_VERIFY_DONE:
				case SEAMLESS_VERIFY_FAILED:
					next_state = &state_table[RUNTIME];
					break;
				default:
					break;
			}
		}
#endif
		if (next_state)
			smf_set_state(SMF_CTX(&s_obj), next_state);

		if (run_state || next_state)
			smf_run_state(SMF_CTX(&s_obj));

		s_obj.event_ctx = NULL;
		k_free(fifo_in);
	}
}

