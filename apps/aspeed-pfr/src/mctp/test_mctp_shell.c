/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#if defined(CONFIG_PFR_MCTP)
#if defined(CONFIG_SHELL)
#include <zephyr.h>
#include <shell/shell.h>
#include "mctp/mctp_interface.h"
#include "mctp_utils.h"
#include "plat_mctp.h"

static uint8_t request_data[256] = {0};
static uint8_t message[512] = {0};

static int cmd_mctp_send_msg(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(shell);

	struct mctp_interface *mctp_interface = NULL;
	mctp *mctp_inst = NULL;
	int req_len = argc - 4;
	int argc_req_idx = 4;
	uint8_t dst_addr;
	uint8_t dst_eid;
	uint8_t bus_num;
	int status;
	int i;

	bus_num = strtol(argv[1], NULL, 16);
	dst_addr = strtol(argv[2], NULL, 16);
	dst_eid = strtol(argv[3], NULL, 16);

	mctp_inst = find_mctp_by_smbus(bus_num);
	if (mctp_inst == NULL) {
		shell_error(shell, "mctp instance not fould");
		return 0;
	}

	mctp_interface = &mctp_inst->mctp_wrapper.mctp_interface;
	// request data
	// request_data[0] =message type
	// request_data[1] = rq
	// request_data[2] = command code
	memset(request_data, 0, sizeof(request_data));
	for (i = 0; i < req_len; i++)
		request_data[i] = strtol(argv[argc_req_idx++], NULL, 16);

	shell_info(shell, "req_len = %d", req_len);
	shell_print(shell, "request:");
	shell_hexdump(shell, request_data, req_len);

	status = mctp_interface_issue_request(mctp_interface, &mctp_inst->mctp_cmd_channel,
		dst_addr, dst_eid, request_data, req_len, message, sizeof(message), 1000);

	if (status != 0)
		shell_error(shell, "mctp issue request failed");
	else {
		shell_print(shell, "response:");
		shell_hexdump(shell, mctp_interface->req_buffer.data, mctp_interface->req_buffer.length);
	}

	return 0;
}

static int cmd_mctp_send_large_msg(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(shell);

	struct mctp_interface *mctp_interface = NULL;
	mctp *mctp_inst = NULL;
	int argc_req_idx = 3;
	uint8_t dst_addr;
	uint8_t dst_eid;
	uint8_t bus_num;
	uint32_t count;
	uint32_t req_len;
	int status;
	int i;

	bus_num = strtol(argv[1], NULL, 16);
	dst_addr = strtol(argv[2], NULL, 16);
	dst_eid = strtol(argv[3], NULL, 16);
	count = strtol(argv[7], NULL, 10);

	shell_print(shell, "cound =%d", count);
	if (count > sizeof(request_data)) {
		shell_print(shell, "count too large");
		return 0;
	}

	mctp_inst = find_mctp_by_smbus(bus_num);
	if (mctp_inst == NULL) {
		shell_error(shell, "mctp instance not fould");
		return 0;
	}

	mctp_interface = &mctp_inst->mctp_wrapper.mctp_interface;
	// request data
	// request_data[0] =message type
	// request_data[1] = rq
	// request_date[2] = command code
	memset(request_data, 0, sizeof(request_data));
	request_data[0] = strtol(argv[4], NULL, 16);
	request_data[1] = strtol(argv[5], NULL, 16);
	request_data[2] = strtol(argv[6], NULL, 16);


	for (i = 0; i < count; i++)
		request_data[argc_req_idx++] = i % 0x100;

	req_len = 3 + count;
	shell_info(shell, "req_len = %d", req_len);
	shell_print(shell, "request:");
	shell_hexdump(shell, request_data, req_len);

	status = mctp_interface_issue_request(mctp_interface, &mctp_inst->mctp_cmd_channel,
		dst_addr, dst_eid, request_data, req_len, message, sizeof(message), 1000);

	if (status != 0)
		shell_error(shell, "mctp issue request failed");
	else {
		shell_print(shell, "response:");
		shell_hexdump(shell, mctp_interface->req_buffer.data, mctp_interface->req_buffer.length);
	}

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_mctp_cmds,
	SHELL_CMD_ARG(send, NULL, "<bus> <dest_addr> <dest_eid> <msg_type> <rq/d/ins> <cmd_code> <option:payload>", cmd_mctp_send_msg, 7, 255),
	SHELL_CMD_ARG(send_large, NULL, "<bus> <dest_addr> <dest_eid> <msg_type> <rq/d/ins> <cmd_code> <msg_count>", cmd_mctp_send_large_msg, 8, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(mctp, &sub_mctp_cmds, "MCTP Commands", NULL);

#endif // CONFIG_SHELL
#endif // CONFIG_PFR_MCTP
