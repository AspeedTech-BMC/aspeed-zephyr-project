/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "logging/debug_log.h"
#include "logging/logging_memory.h"

#define LOGGING_ENTRY_COUNT 32
#define LOGGING_ENTRY_LENGTH sizeof(struct debug_log_entry_info)
#define LOGGING_BUF_SIZE (LOGGING_ENTRY_COUNT * LOGGING_ENTRY_LENGTH)

/**
 * logging memory wrapper.
 */
struct logging_memory_wrapper {
	struct logging_memory_state state;	/* Variable context for a log that stores data in volatile memory. */
	struct logging_memory logging;		/* A log that will store entries in volatile memory */
};

int debug_log_init(void);
void debug_log_release(void);
void debug_msg_display(void);

