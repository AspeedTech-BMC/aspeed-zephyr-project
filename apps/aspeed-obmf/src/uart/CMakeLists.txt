# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0

# The UART channel is always exported. lstp_uart.c holds what the backends
# share; exactly one backend is linked. The Kconfig symbols already fold in
# whether the vuart0 node is enabled and exclude each other.
target_sources(app PRIVATE lstp_uart.c)

if(CONFIG_OBMF_ESPI_UART_VUART)
target_sources(app PRIVATE lstp_uart_vuart.c)
elseif(CONFIG_OBMF_LSTP_UART_SHELL)
target_sources(app PRIVATE lstp_uart_shell.c)
else()
target_sources(app PRIVATE lstp_uart_plain.c)
endif()
