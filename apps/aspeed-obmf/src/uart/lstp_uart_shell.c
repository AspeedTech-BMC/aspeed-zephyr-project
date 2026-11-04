/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * LSTP UART backend with no UART behind it: the shell stands in for the far
 * end of the BMC's ttyLSTP. Bytes the BMC writes are kept in a ring for
 * "obmf uart recv"; "obmf uart send" pushes text to the BMC. Built
 * when CONFIG_OBMF_LSTP_UART_SHELL is set.
 */

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/sys/util.h>

#include "lstp_uart.h"
#include "lstp_uart_backend.h"

RING_BUF_DECLARE(lstp_uart_shell_rx_ring, LSTP_UART_MIRROR_BUF_SIZE);
static struct k_spinlock lstp_uart_shell_lock;

int lstp_uart_init(void)
{
	lstp_uart_host_active = true;
	return 0;
}

/* Called from the LSTP task with what the BMC wrote; never pushes back. */
int lstp_uart_tx_bytes(const uint8_t *data, size_t len)
{
	k_spinlock_key_t key;
	uint32_t put;

	if (data == NULL || len == 0U) {
		return 0;
	}

	key = k_spin_lock(&lstp_uart_shell_lock);
	if (ring_buf_space_get(&lstp_uart_shell_rx_ring) < len) {
		/* All or nothing: NAK tells the host the write was not taken. */
		k_spin_unlock(&lstp_uart_shell_lock, key);
		atomic_inc(&lstp_uart_tx_nak_events);
		return -EBUSY;
	}
	put = ring_buf_put(&lstp_uart_shell_rx_ring, data, len);
	k_spin_unlock(&lstp_uart_shell_lock, key);
	ARG_UNUSED(put);

	return 0;
}

void lstp_uart_backend_host_reset(void)
{
	/* Nothing is buffered towards the BMC. */
}

void lstp_uart_resume_forwarding(void)
{
	/* Nothing is buffered towards the BMC; "send" goes out immediately. */
}

static int cmd_lstp_uart_send(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t buf[LSTP_MAX_PAYLOAD_SIZE];
	size_t len = 0;
	int ret;

	/* Join the arguments with spaces and end the line, as a terminal would. */
	for (size_t i = 1; i < argc; i++) {
		size_t arg_len = strlen(argv[i]);

		if (len + arg_len + 2U > sizeof(buf)) {
			shell_error(sh, "Text exceeds %zu bytes", sizeof(buf) - 1U);
			return -EINVAL;
		}
		if (i > 1) {
			buf[len++] = ' ';
		}
		memcpy(&buf[len], argv[i], arg_len);
		len += arg_len;
	}
	buf[len++] = '\n';

	ret = lstp_uart_send_to_host(buf, len);
	if (ret < 0) {
		shell_error(sh, "Send failed: %d", ret);
		return ret;
	}

	return 0;
}

static int cmd_lstp_uart_recv(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t buf[LSTP_MAX_PAYLOAD_SIZE];
	k_spinlock_key_t key;
	uint32_t len;
	size_t total = 0;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	do {
		key = k_spin_lock(&lstp_uart_shell_lock);
		len = ring_buf_get(&lstp_uart_shell_rx_ring, buf, sizeof(buf));
		k_spin_unlock(&lstp_uart_shell_lock, key);

		if (len > 0U) {
			shell_hexdump(sh, buf, len);
			total += len;
		}
	} while (len == sizeof(buf));

	shell_print(sh, "%zu bytes", total);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_lstp_uart,
	SHELL_CMD_ARG(send, NULL, "Send a line to the BMC's ttyLSTP: <text...>",
		      cmd_lstp_uart_send, 2, 255),
	SHELL_CMD_ARG(recv, NULL, "Dump and clear what the BMC wrote to ttyLSTP",
		      cmd_lstp_uart_recv, 1, 0),
	SHELL_SUBCMD_SET_END);

SHELL_SUBCMD_ADD((obmf), uart, &sub_lstp_uart,
		 "Talk to the BMC's ttyLSTP from the shell (no UART attached)", NULL, 1, 0);
