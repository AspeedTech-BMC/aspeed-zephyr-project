/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/shell/shell.h>
#include <zephyr/sys/util.h>

#include "gpio/lstp_gpio.h"
#include "uart/lstp_uart.h"
#include "lstp/lstp_usb.h"

static int cmd_lstp_stats(const struct shell *sh, size_t argc, char **argv)
{
	struct lstp_uart_stats uart;
	struct lstp_usb_stats usb;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	lstp_uart_get_stats(&uart);
	lstp_usb_get_stats(&usb);

	shell_print(sh, "UART drops (bytes)");
	shell_print(sh, "  RX ring overflow: %u", uart.rx_dropped_bytes);
	shell_print(sh, "  RX FIFO overruns: %u  (LSR.OE events, not bytes)",
		    uart.rx_fifo_overruns);
	shell_print(sh, "  TX dropped      : %u  (host not draining VUART)",
		    uart.tx_dropped_bytes);
	shell_print(sh, "  TX NAK events   : %u  (host-to-UART writes, backend buffer full)",
		    uart.tx_nak_events);
	shell_print(sh, "  RX fwd dropped  : %u  (bytes, no host or host reset)",
		    uart.rx_forward_dropped_bytes);
	shell_print(sh, "USB transport");
	shell_print(sh, "  response drops  : %u", usb.response_drops);
	shell_print(sh, "  event drops     : %u  (USB event queue full, caller may retry)",
		    usb.event_drops);
	shell_print(sh, "  rx drops        : %u", usb.rx_drops);
	shell_print(sh, "  write errors    : %u", usb.write_errors);
	shell_print(sh, "  tx queue peak   : %u", usb.tx_high_water);
	if (IS_ENABLED(CONFIG_OBMF_LSTP_GPIO_CHANNEL)) {
		shell_print(sh, "LSTP GPIO");
		shell_print(sh, "  gpio irq drops  : %u", lstp_gpio_get_irq_drops());
		shell_print(sh, "  gpio event drops: %u  (sent but rejected by USB)",
			    lstp_gpio_get_event_drops());
	}

	return 0;
}

SHELL_SUBCMD_SET_CREATE(sub_obmf, (obmf));

SHELL_SUBCMD_ADD((obmf), stats, NULL, "Show LSTP drop/queue counters",
		 cmd_lstp_stats, 1, 0);

SHELL_CMD_REGISTER(obmf, &sub_obmf, "OBMF demo commands ('select obmf <node>' to stay inside one)",
		   NULL);
