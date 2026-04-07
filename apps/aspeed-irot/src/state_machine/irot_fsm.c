/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/logging/log.h>
#include <zephyr/smf.h>
#include <zephyr/drivers/misc/aspeed/cptra_ipc.h>
#include <zephyr/drivers/ipm.h>
#include <zephyr/multi_heap/shared_multi_heap.h>

#include <state_machine/irot_fsm.h>
#include <psp/loader.h>
#include <image/caliptra_soc_manifest.h>
#include <image/caliptra_soc_manifest_v1.h>
#include <mctp_init.h>

LOG_MODULE_REGISTER(irot_fsm, LOG_LEVEL_DBG);

#define NONCACHE_NODE DT_NODELABEL(dram_nc_region)
#define NONCACHE_ADDR DT_REG_ADDR(NONCACHE_NODE)
#define NONCACHE_SIZE DT_REG_SIZE(NONCACHE_NODE)


struct irot_state_obj {
	struct smf_ctx smf_ctx;

	/* Add user defined variables below */
	enum IROT_EVENT current_event;
};

/* Init State */
static void test_ipm_cb(const struct device *dev, void *user_data,
		uint32_t id, volatile void *data)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(id);
	ARG_UNUSED(data);

	LOG_DBG("Received IPC message with id: %d", id);
}

static void ca35_ns_ipc_enable(void)
{
	const struct device *ipmdev = device_get_binding("ipc0@200");
	int ret, device_id = 0;

	if (!ipmdev) {
		LOG_ERR("Failed to get IPC device binding");
		return;
	}

	ipm_register_id_callback(ipmdev, device_id, test_ipm_cb, NULL);
	ret = ipm_set_id_enabled(ipmdev, device_id, true);

}

static void do_init_entry(void *state)
{
	struct irot_state_obj *state_obj = (struct irot_state_obj *)state;
	ARG_UNUSED(state_obj);

	LOG_DBG("iRoT FSM entry INIT state");

	// Init shared multi heap for non-cacheable memory allocation
	shared_multi_heap_pool_init();
	struct shared_multi_heap_region region = {
		.addr = NONCACHE_ADDR,
		.size = NONCACHE_SIZE,
		.attr = SMH_REG_ATTR_NON_CACHEABLE,
	};
	shared_multi_heap_add(&region, NULL);
	
	/* Add user defined init code here */
	cptra_ipc_enable();

	mctp_init_app();

	irot_send_event(INIT_DONE, NULL);
}

/* Verify State */

static void do_verify_run(void *state)
{
	struct irot_state_obj *state_obj = (struct irot_state_obj *)state;
	ARG_UNUSED(state_obj);

	LOG_DBG("iRoT FSM running VERIFY state");

	// Get from bmc_pfm node in dts
	const struct device *man_dev = NULL, *fmc_dev = NULL;
	uint32_t offset = 0;
	struct cptra_flash_header_v1 v1_header = { 0 };
	int ret;
	man_dev = device_get_binding("fmc@0");
	if (man_dev != NULL && flash_read(man_dev, 0, &v1_header, sizeof(v1_header)) == 0 &&
	    v1_header.magic == CPTRA_FLASH_HEADER_MAGIC) {
		fmc_dev = man_dev;
		ret = cptra_soc_manifest_v1_handler.verify_manifest(man_dev, fmc_dev, offset);
	} else {
		man_dev = device_get_binding("fmc@1");
		fmc_dev = device_get_binding("fmc@0");
		ret = cptra_soc_manifest_handler.verify_manifest(man_dev, fmc_dev, offset);
	}
	
	if (ret == 0) {
		LOG_INF("Manifest verification successful");
		irot_send_event(VERIFY_DONE, NULL);
	} else {
		LOG_ERR("Manifest verification failed");
		irot_send_event(VERIFY_FAILED, NULL);
	}

}

/* Arming State */
static void do_arming_run(void *state)
{
	struct irot_state_obj *state_obj = (struct irot_state_obj *)state;
	ARG_UNUSED(state_obj);

	LOG_DBG("iRoT FSM running ARMING state");

	/* Setup FMC SPI Filter */

	/* Setup eDAF Filter */

	// For demo purposes, we will just send ARMING_DONE event
	irot_send_event(ARMING_DONE, NULL);
}

/* Runtime State */
static void do_runtime_entry(void *state)
{
	struct irot_state_obj *state_obj = (struct irot_state_obj *)state;
	ARG_UNUSED(state_obj);

	LOG_DBG("iRoT FSM entered RUNTIME state");

	LOG_INF("Bring up the primary processor");
	aspeed_prepare_for_boot();
}

static void do_runtime_run(void *state)
{
	struct irot_state_obj *state_obj = (struct irot_state_obj *)state;
	ARG_UNUSED(state_obj);

	LOG_DBG("iRoT FSM running RUNTIME state");
	/* Add user defined runtime code here */
}

const struct smf_state irot_fsm_states[] = {
	// SMF_CREATE_STATE ( _entry, _run, _exit, _parent, _initial )
	[BOOT] = SMF_CREATE_STATE( NULL, NULL, NULL, NULL, NULL),
	[INIT] = SMF_CREATE_STATE( do_init_entry, NULL, NULL, NULL, NULL),
	[VERIFY] = SMF_CREATE_STATE( NULL, do_verify_run, NULL, NULL, NULL),
	[ARMING] = SMF_CREATE_STATE( NULL, do_arming_run, NULL, NULL, NULL),
	[RUNTIME] = SMF_CREATE_STATE( do_runtime_entry, do_runtime_run, NULL, NULL, NULL),
	[UPDATE] = SMF_CREATE_STATE( NULL, NULL, NULL, NULL, NULL),
	[DEINIT] = SMF_CREATE_STATE( NULL, NULL, NULL, NULL, NULL),
	[PANIC] = SMF_CREATE_STATE( NULL, NULL, NULL, NULL, NULL),
};

K_MSGQ_DEFINE(irot_event_queue, sizeof(struct irot_event_msg), 10, 4);

void irot_send_event(enum IROT_EVENT event, void *data)
{
	struct irot_event_msg event_msg;

	event_msg.event = event;
	event_msg.data = data;

	if (k_msgq_put(&irot_event_queue, &event_msg, K_NO_WAIT) != 0) {
		LOG_WRN("iRoT FSM event queue full, dropping event: %d", event);
	}
}

const char *irot_state_to_string(void *state)
{
	if (state == &irot_fsm_states[BOOT]) {
		return "BOOT";
	} else if (state == &irot_fsm_states[INIT]) {
		return "INIT";
	} else if (state == &irot_fsm_states[VERIFY]) {
		return "VERIFY";
	} else if (state == &irot_fsm_states[ARMING]) {
		return "ARMING";
	} else if (state == &irot_fsm_states[RUNTIME]) {
		return "RUNTIME";
	} else if (state == &irot_fsm_states[UPDATE]) {
		return "UPDATE";
	} else if (state == &irot_fsm_states[DEINIT]) {
		return "DEINIT";
	} else if (state == &irot_fsm_states[PANIC]) {
		return "PANIC";
	}
	return "UNKNOWN";
}

static void irot_fsm_thread_entry(void *arg1, void *arg2, void *arg3)
{
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);
	ARG_UNUSED(arg3);
	
	int32_t ret;
	struct irot_state_obj irot_fsm_obj;

	LOG_INF("iRoT FSM thread started");
	smf_set_initial(SMF_CTX(&irot_fsm_obj), &irot_fsm_states[BOOT]);

	while (1) {
		enum IROT_EVENT irot_event;
		struct irot_event_msg event_msg;

		const struct smf_state *current_state = irot_fsm_obj.smf_ctx.current;
		const struct smf_state *next_state = NULL;

		if (k_msgq_get(&irot_event_queue, &event_msg, K_MSEC(60000)) == 0) {
			irot_event = event_msg.event;
			LOG_INF("iRoT FSM received event: %d", irot_event);
		} else {
			LOG_DBG("iRoT FSM current state: %s[%p]",
					irot_state_to_string((void *)current_state),
					(void *)current_state);
			continue;
		}
		irot_fsm_obj.current_event = irot_event;

		// Create all state transitions here
		if (current_state == &irot_fsm_states[BOOT]) {
			switch (irot_event) {
				case START_STATE_MACHINE:
					next_state = &irot_fsm_states[INIT];
					break;
				default:
					break;
			}
		} else if (current_state == &irot_fsm_states[INIT]) {
			switch (irot_event) {
				case INIT_DONE:
					next_state = &irot_fsm_states[VERIFY];
					break;
				case INIT_FAILED:
					next_state = &irot_fsm_states[PANIC];
					break;
				default:
					break;
			}
		} else if (current_state == &irot_fsm_states[VERIFY]) {
			switch (irot_event) {
				case VERIFY_DONE:
					next_state = &irot_fsm_states[ARMING];
					break;
				case VERIFY_FAILED:
					next_state = &irot_fsm_states[DEINIT];
					break;
				case VERIFY_SKIPED:
					next_state = &irot_fsm_states[RUNTIME];
					break;
				default:
					break;
			}
		} else if (current_state == &irot_fsm_states[ARMING]) {
			switch (irot_event) {
				case ARMING_DONE:
					next_state = &irot_fsm_states[RUNTIME];
					break;
				case ARMING_FAILED:
					next_state = &irot_fsm_states[DEINIT];
					break;
				default:
					break;
			}
		} else if (current_state == &irot_fsm_states[RUNTIME]) {
			switch (irot_event) {
				case UPDATE_REQUESTED:
					next_state = &irot_fsm_states[UPDATE];
					break;
				default:
					break;
			}
		} else if (current_state == &irot_fsm_states[UPDATE]) {
			switch (irot_event) {
				case UPDATE_COMPLETED:
					next_state = &irot_fsm_states[DEINIT];
					break;
				case UPDATE_FAILED:
					next_state = &irot_fsm_states[RUNTIME];
					break;
				default:
					break;
			}
		} else if (current_state == &irot_fsm_states[DEINIT]) {
		} else if (current_state == &irot_fsm_states[PANIC]) {
		}


		if (next_state != NULL) {
			LOG_DBG("iRoT FSM transitioning from state %p to state %p",
				current_state, next_state);
			smf_set_state(SMF_CTX(&irot_fsm_obj), next_state);
		}

		ret = smf_run_state(SMF_CTX(&irot_fsm_obj));

		if (ret < 0) {
			LOG_ERR("iRoT FSM encountered error: %d", ret);
		}
	}
}

K_THREAD_DEFINE(irot_fsm_tid,
		16384,
		irot_fsm_thread_entry,
		NULL, NULL, NULL,
		5,
		0, 0);
