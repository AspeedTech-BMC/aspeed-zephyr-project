/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdbool.h>

struct platform_monitor_ctrl_ops {
	void (*init)(void);
	void (*remove)(void);
	void (*power_btn)(bool assert);
};

const struct platform_monitor_ctrl_ops *get_platform_monitor_ctrl_ops(void);
