# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

# The UART channel is always exported. lstp_uart.c holds what the backends
# share; exactly one backend is linked.
target_sources(app PRIVATE lstp_uart.c)

if(CONFIG_OBMF_LSTP_UART_SHELL)
target_sources(app PRIVATE lstp_uart_shell.c)
else()
target_sources(app PRIVATE lstp_uart_plain.c)
endif()
