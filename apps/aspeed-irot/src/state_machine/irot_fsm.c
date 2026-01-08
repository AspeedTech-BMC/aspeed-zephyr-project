/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/smf.h>

#include <state_machine/irot_fsm.h>
#include <psp/loader.h>

LOG_MODULE_REGISTER(irot_fsm, LOG_LEVEL_DBG);

struct irot_state_obj {
	struct smf_ctx smf_ctx;

	/* Add user defined variables below */
	enum IROT_EVENT current_event;
};

/* Init State */
static void do_init_run(void *state)
{
	struct irot_state_obj *state_obj = (struct irot_state_obj *)state;
	ARG_UNUSED(state_obj);

	LOG_DBG("iRoT FSM running INIT state");
	/* Add user defined init code here */
}

/* Runtime State */
static void do_runtime_entry(void *state)
{
	struct irot_state_obj *state_obj = (struct irot_state_obj *)state;
	ARG_UNUSED(state_obj);

	LOG_DBG("iRoT FSM entered RUNTIME state");

	LOG_INF("Bring up the primary processor");
	aspeed_load_image("ATF");
	aspeed_load_image("UBOOT");
	aspeed_load_image("TEE");
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
	[INIT] = SMF_CREATE_STATE( NULL, do_init_run, NULL, NULL, NULL),
	[VERIFY] = SMF_CREATE_STATE( NULL, NULL, NULL, NULL, NULL),
	[ARMING] = SMF_CREATE_STATE( NULL, NULL, NULL, NULL, NULL),
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

static void irot_fsm_thread_entry(void *arg1, void *arg2, void *arg3)
{
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);
	ARG_UNUSED(arg3);
	
	int32_t ret;
	struct irot_state_obj irot_fsm_obj;

	LOG_INF("iRoT FSM thread started");
	smf_set_initial(SMF_CTX(&irot_fsm_obj), &irot_fsm_states[INIT]);

	while (1) {
		enum IROT_EVENT irot_event;
		struct irot_event_msg event_msg;

		const struct smf_state *current_state = irot_fsm_obj.smf_ctx.current;
		const struct smf_state *next_state = NULL;

		if (k_msgq_get(&irot_event_queue, &event_msg, K_MSEC(1000)) == 0) {
			irot_event = event_msg.event;
			LOG_DBG("iRoT FSM received event: %d", irot_event);
		} else {
			continue;
		}
		irot_fsm_obj.current_event = irot_event;

		// Create all state transitions here
		if (current_state == &irot_fsm_states[INIT]) {
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
		2048,
		irot_fsm_thread_entry,
		NULL, NULL, NULL,
		5,
		0, 0);

