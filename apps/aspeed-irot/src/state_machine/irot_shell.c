/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <state_machine/irot_fsm.h>
#include <zephyr/shell/shell.h>

// Send event
static int cmd_irot_send_event(const struct shell *shell, size_t argc, char **argv, void *data)
{
	enum IROT_EVENT event = (enum IROT_EVENT)data;

	irot_send_event(event, NULL);
	
	shell_print(shell, "iRoT FSM event %d sent", event);
	
	return 0;
}

SHELL_SUBCMD_DICT_SET_CREATE(sub_event, cmd_irot_send_event,
	(INIT_DONE, INIT_DONE, "Init Done"),
	(INIT_FAILED, INIT_FAILED, "Init Failed"),
	(VERIFY_DONE, VERIFY_DONE, "Verify Done"),
	(VERIFY_FAILED, VERIFY_FAILED, "Verify Failed"),
	(VERIFY_SKIPED, VERIFY_SKIPED, "Verify Skiped"),
	(ARMING_DONE, ARMING_DONE, "Arming Done"),
	(ARMING_FAILED, ARMING_FAILED, "Arming Failed"),
	(UPDATE_REQUESTED, UPDATE_REQUESTED, "Update Requested"),
	(UPDATE_COMPLETED, UPDATE_COMPLETED, "Update Completed"),
	(UPDATE_FAILED, UPDATE_FAILED, "Update Failed")
);

SHELL_STATIC_SUBCMD_SET_CREATE( sub_irot,
	SHELL_CMD(event, &sub_event, "iRoT FSM event commands", NULL),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(irot, &sub_irot, "iRoT FSM commands", NULL);
