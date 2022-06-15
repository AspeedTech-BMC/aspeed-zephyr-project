/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr.h>
#include <smf.h>
#include <shell/shell.h>
#include <logging/log.h>
#include <drivers/i2c/pfr/swmbx.h>
#include <drivers/misc/aspeed/abr_aspeed.h>

#include "AspeedStateMachine.h"
#include "include/SmbusMailBoxCom.h"
#include "intel_pfr/intel_pfr_definitions.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "pfr/pfr_util.h"
#include "gpio/gpio_aspeed.h"
#include "platform_monitor/platform_monitor.h"
#include "engineManager/engine_manager.h"
#include "spi_filter/spi_filter_wrapper.h"
#include "flash/flash_aspeed.h"

LOG_MODULE_REGISTER(aspeed_state_machine, LOG_LEVEL_DBG);
K_FIFO_DEFINE(aspeed_sm_fifo);
struct smf_context s_obj;
static const struct smf_state state_table[];

enum aspeed_pfr_event event_log[128] = {START_STATE_MACHINE};
size_t event_log_idx = 0;

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

	initializeEngines();
	initializeManifestProcessor();
	debug_log_init();// State Machine log saving

	// DEBUG_HALT();
	pfr_bmc_srst_enable_ctrl(true);
	BMCBootHold();
	PCHBootHold();

	state->bmc_active_object.type = BMC_EVENT;
	state->bmc_active_object.ActiveImageStatus = Failure;
	state->bmc_active_object.RecoveryImageStatus = Failure;
	state->bmc_active_object.RestrictActiveUpdate = Failure;

	state->pch_active_object.type = PCH_EVENT;
	state->pch_active_object.ActiveImageStatus = Failure;
	state->pch_active_object.RecoveryImageStatus = Failure;
	state->pch_active_object.RestrictActiveUpdate = Failure;

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
		SetPlatformState(CPLD_NIOS_II_PROCESSOR_STARTED);
#endif

		// TODO: Wait for Power Sequence signal to leave INIT state
		//       Populate INIT_DONE event will enter FIRMWARE_VERIFY state
		GenerateStateMachineEvent(INIT_DONE, NULL);
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
	struct smf_context *state = (struct smf_context*)o;
	struct event_context *evt_ctx = ((struct smf_context *)o)->event_ctx;
	// BMC Verify tri-state
	int verify_recovery = -1, verify_active = -1;
	int ret;


	byte provision_state = GetUfmStatusValue();

	if (!(provision_state & UFM_PROVISIONED)) {
		// Unprovisioned, populate INIT_UNPROVISIONED event will enter UNPROVISIONED state
		GenerateStateMachineEvent(VERIFY_UNPROVISIONED, NULL);
	} else {
		/* BMC Verification */
		{
			SetPlatformState(BMC_FLASH_AUTH);
			{
				EVENT_CONTEXT evt_wrap;
				evt_wrap.image = BMC_EVENT;
				evt_wrap.operation = VERIFY_BACKUP;
				evt_wrap.flash = SECONDARY_FLASH_REGION;
				ret = authentication_image(NULL, &evt_wrap);
				LOG_INF("authentication_image bmc backup return %d", ret);
				if (ret == 0) {
					verify_recovery = true;
					state->bmc_active_object.RecoveryImageStatus = Success;
				} else {
					verify_recovery = false;
					state->bmc_active_object.RecoveryImageStatus = Failure;
				}
			}

			{
				EVENT_CONTEXT evt_wrap;
				evt_wrap.image = BMC_EVENT;
				evt_wrap.operation = VERIFY_ACTIVE;
				ret = authentication_image(NULL, &evt_wrap);
				LOG_INF("authentication_image bmc active return %d", ret);
				if (ret == 0) {
					verify_active = true;
					state->bmc_active_object.ActiveImageStatus = Success;
				} else {
					verify_active = false;
					state->bmc_active_object.ActiveImageStatus = Failure;
				}
			}
		}

		/* PCH Verification */
		{
			SetPlatformState(PCH_FLASH_AUTH);
			{
				EVENT_CONTEXT evt_wrap;
				evt_wrap.image = PCH_EVENT;
				evt_wrap.operation = VERIFY_BACKUP;
				evt_wrap.flash = SECONDARY_FLASH_REGION;
				ret = authentication_image(NULL, &evt_wrap);
				LOG_INF("authentication_image host backup return %d", ret);
				if (ret == 0) {
					state->pch_active_object.RecoveryImageStatus = Success;
				} else {
					state->pch_active_object.RecoveryImageStatus = Failure;
				}
			}

			{
				EVENT_CONTEXT evt_wrap;
				evt_wrap.image = PCH_EVENT;
				evt_wrap.operation = VERIFY_ACTIVE;
				evt_wrap.flash = PRIMARY_FLASH_REGION;
				ret = authentication_image(NULL, &evt_wrap);
				LOG_INF("authentication_image host active return %d", ret);
				if (ret == 0) {
					state->pch_active_object.ActiveImageStatus = Success;
				} else {
					state->pch_active_object.ActiveImageStatus = Failure;
				}
			}
		}

		LOG_INF("BMC image verification recovery=%d active=%d",
				verify_recovery, verify_active);

		if (verify_active) {
			if (verify_recovery) {
				// Good, Good, Don't care: No action
				state->bmc_active_object.RestrictActiveUpdate = 0;
				GenerateStateMachineEvent(VERIFY_DONE, NULL);
			} else {
				// Good, Bad, *: copy staging to recovery
				state->bmc_active_object.RestrictActiveUpdate = 1;
				GenerateStateMachineEvent(VERIFY_DONE, NULL);
			}
		} else {
			if (verify_recovery) {
				// Bad, Good, Don't care: active currupt, recovery action.
				state->bmc_active_object.RestrictActiveUpdate = 0;
				GenerateStateMachineEvent(VERIFY_ACT_FAILED, NULL);
			} else {
				// Bad, Bad, *: critical platform error
				state->bmc_active_object.RestrictActiveUpdate = 0;
				GenerateStateMachineEvent(VERIFY_RCV_FAILED, NULL);
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
	int verify_staging = -1;
	EVENT_CONTEXT evt_wrap;

	recovery_initialize();

	/* TODO: Verify Staging? */
	if (verify_staging) {
		SetPlatformState(T_MINUS_1_FW_RECOVERY);
		switch (evt_ctx->event) {
		case WDT_TIMEOUT:
			SetPlatformState(WDT_TIMEOUT_RECOVERY);
			state->bmc_active_object.ActiveImageStatus = Failure;
			__attribute__ ((fallthrough));
		case VERIFY_ACT_FAILED:
			// WDT Checkpoint Timeout
			// Bad, Good, Good: Recovery -> Active 
			evt_wrap.image = BMC_EVENT;
			ret = recover_image(&state->bmc_active_object, &evt_wrap);
			LOG_INF("Recovery Active Region return=%d", ret);
			if (ret == Success || ret == VerifyActive) {
				recovery_done = 1;
			}
			break;
		case VERIFY_RCV_FAILED:
			// Good(n), Bad, Good(n): Staging -> Recovery
			// Bad, Bad, Good(x): Staging -> Recovery -> Active
			evt_wrap.image = BMC_EVENT;
			ret = recover_image(&state->bmc_active_object, &evt_wrap);
			LOG_INF("Recovery Recovery Region return=%d", ret);
			if (ret == Success || ret == VerifyRecovery) {
				recovery_done = 1;
			}
			break;
		default:
			break;
		}
	} else {
		switch (evt_ctx->event) {
		case VERIFY_RCV_FAILED:
			// Good(n), bad, bad: System boot but restricted firmware upgrade.

			break;
		case VERIFY_ACT_FAILED:
			// Bad, Bad, Bad: Critical platform error.
			break;
		default:
			break;
		}
	}

	if (recovery_done) {
		GenerateStateMachineEvent(RECOVERY_DONE, NULL);
	} else {
		GenerateStateMachineEvent(RECOVERY_FAILED, NULL);
	}
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

	/* TODO: Overwrite active region with recovery region firmware */
	clear_abr_indicator();
	GenerateStateMachineEvent(RECOVERY_DONE, NULL);
	LOG_DBG("End");
}

void enter_tzero(void *o)
{
	LOG_DBG("Start");
	SetPlatformState(ENTER_T0);

	struct smf_context *state = (struct smf_context*)o;
	/* Arm reset monitor */
	platform_monitor_init();
#if defined(CONFIG_ASPEED_DC_SCM)
	pfr_bmc_srst_enable_ctrl(false);
#endif
	if (state->ctx.current == &state_table[RUNTIME]) {
		/* Provisioned */
		/* Arm SPI/I2C Filter */
		apply_pfm_protection(BMC_SPI);
		/* Releasing System Reset */
		if (state->bmc_active_object.ActiveImageStatus == Success) {
			BMCBootRelease();
		} else {
			/* Should not enter here, redirect to LOCKDOWN */
			LOG_ERR("BMC firmware is invalid, lockdown the platform");
		}

		if (state->pch_active_object.ActiveImageStatus == Success) {
			PCHBootRelease();
		} else {
			LOG_ERR("Host firmware is invalid, host won't boot");
		}
	} else {
		/* Unprovisioned - Releasing System Reset */
		Set_SPI_Filter_RW_Region("spi_m1", SPI_FILTER_READ_PRIV, SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
		Set_SPI_Filter_RW_Region("spi_m1", SPI_FILTER_WRITE_PRIV, SPI_FILTER_PRIV_ENABLE, 0, 0x10000000);
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

	if (evt_ctx->data.bit8[1] & EXECUTE_UFM_COMMAND) {
		LOG_DBG("UFM Trigger Execute");
		ClearUfmStatusValue(UFM_CLEAR_ON_NEW_COMMAND);
		SetUfmStatusValue(COMMAND_BUSY);
		process_provision_command();
		SetUfmStatusValue(COMMAND_DONE);
	} else if (evt_ctx->data.bit8[1] & FLUSH_WRITE_FIFO) {
		memset(&gUfmFifoData, 0, sizeof(gUfmFifoData));
		swmbx_flush_fifo(gSwMbxDev, UfmWriteFIFO);
		gFifoData = 0;
	} else if (evt_ctx->data.bit8[1] & FLUSH_READ_FIFO) {
		memset(&gReadFifoData, 0, sizeof(gReadFifoData)); 
		swmbx_flush_fifo(gSwMbxDev, UfmReadFIFO); 
		gFifoData = 0; 
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
	bool update_dynamic = evt_ctx->data.bit8[1] & DymanicUpdate;
	bool update_reset = evt_ctx->data.bit8[1] & UpdateAtReset;

	LOG_DBG("FIRMWARE_UPDATE Event Data %02x %02x", evt_ctx->data.bit8[0], evt_ctx->data.bit8[1]);

	switch(evt_ctx->data.bit8[0]) {
	case PchUpdateIntent:
		/* CPU/PCH only has access to bit[7:6] and bit[1:0] */
		update_region &= UpdateAtReset | DymanicUpdate | PchRecoveryUpdate | PchActiveUpdate;
		break;
	case BmcUpdateIntent:
		/* BMC has full access */
		break;
	default:
		break;
	}

	if (!update_reset) {
		uint32_t handled_region = 0;
		while(update_region) {
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

			if (image_type != 0xFFFFFFFF) {
				ret = update_firmware_image(image_type, ao_data_wrap, &evt_ctx_wrap);
			}

			if (ret != Success) {
				/* TODO: Log failed reason and handle it properly */
				GenerateStateMachineEvent(UPDATE_FAILED, (void *)handled_region);
				break;
			}
		}

		if (update_region == 0 && ret == Success) {
			GenerateStateMachineEvent(UPDATE_DONE, (void *)handled_region);
		}
	}
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
	AspeedPFR_EnableTimer(BMC_EVENT);
	//AspeedPFR_EnableTimer(PCH_EVENT);
	LOG_DBG("End");
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
	LOG_INF("ROT going to reboot in 1 second");
	k_msleep(1000);
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


void AspeedStateMachine()
{
	smf_set_initial(SMF_CTX(&s_obj), &state_table[BOOT]);
	GenerateStateMachineEvent(START_STATE_MACHINE, NULL);

	while (1) {
		struct event_context *fifo_in = (struct event_context *)k_fifo_get(&aspeed_sm_fifo, K_FOREVER);
		if (fifo_in == NULL) {
			continue;
		}
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
			case VERIFY_UNPROVISIONED:
				next_state = &state_table[UNPROVISIONED];
				break;
			case VERIFY_PFM_FAILED:
			case VERIFY_STG_FAILED:
			case VERIFY_RCV_FAILED:
			case VERIFY_ACT_FAILED:
				next_state = &state_table[FIRMWARE_RECOVERY];
				break;
			case VERIFY_DONE:
				// Firmware is authenticated -> RUNTIME
				// Non provisioned -> UNPROVISIONED
				next_state = &state_table[RUNTIME];
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
				// Check update intent, seamless or tmin1 update
				next_state = &state_table[FIRMWARE_UPDATE];
				break;
			case PROVISION_CMD:
			case WDT_CHECKPOINT:
				// Just run provision handling
				run_state = true;
				break;
			case WDT_TIMEOUT:
				next_state = &state_table[FIRMWARE_RECOVERY];
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

		if (next_state) {
			smf_set_state(SMF_CTX(&s_obj), next_state);
		}

		if (run_state || next_state) {
			smf_run_state(SMF_CTX(&s_obj));
		}

		s_obj.event_ctx = NULL;
		k_free(fifo_in);
	}
}

#ifdef CONFIG_SHELL
static int cmd_smf_event(const struct shell *shell,
		         size_t argc, char **argv, void *data)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	shell_print(shell, "Sending event[%d]\n", data);
	GenerateStateMachineEvent((enum aspeed_pfr_event)data, NULL);

	return 0;
}

static int cmd_smf_show(const struct shell *shell, size_t argc,
                        char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	shell_print(shell, "State List:");
	for (int i=0; i < ARRAY_SIZE(state_table); ++i) {
		shell_print(shell, "[%d] %p", i, &state_table[i]);
	}
	shell_print(shell, "Current state: %p", SMF_CTX(&s_obj)->current);
	return 0;
}

static int cmd_smf_log(const struct shell *shell, size_t argc,
                        char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	shell_print(shell, "Event Count = %d\n", event_log_idx);
	shell_hexdump(shell, event_log, sizeof(event_log));
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_smf,
        SHELL_CMD(show, NULL, "Show current state machine state", cmd_smf_show),
	SHELL_CMD(log, NULL, "Show state machine event log", cmd_smf_log),
        SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(smf, &sub_smf, "State Machine Commands", NULL);

SHELL_SUBCMD_DICT_SET_CREATE(sub_event, cmd_smf_event,
	(INIT_DONE, INIT_DONE),
	(VERIFY_UNPROVISIONED, VERIFY_UNPROVISIONED),
	(VERIFY_PFM_FAILED, VERIFY_PFM_FAILED),
	(VERIFY_STG_FAILED, VERIFY_STG_FAILED),
	(VERIFY_RCV_FAILED, VERIFY_RCV_FAILED),
	(VERIFY_ACT_FAILED, VERIFY_ACT_FAILED),
	(VERIFY_DONE, VERIFY_DONE),
	(RECOVERY_DONE, RECOVERY_DONE),
	(RECOVERY_FAILED, RECOVERY_FAILED),
	(RESET_DETECTED, RESET_DETECTED),
	(UPDATE_REQUESTED, UPDATE_REQUESTED),
	(UPDATE_DONE, UPDATE_DONE),
	(UPDATE_FAILED, UPDATE_FAILED),
	(PROVISION_CMD, PROVISION_CMD),
	(WDT_TIMEOUT, WDT_TIMEOUT)
);

SHELL_CMD_REGISTER(event, &sub_event, "State Machine Events", NULL);
#endif
