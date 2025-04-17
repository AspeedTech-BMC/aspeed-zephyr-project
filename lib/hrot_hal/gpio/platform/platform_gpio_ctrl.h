/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdbool.h>

struct platform_gpio_ctrl_ops {
	void (*pch_hold)(void);
	void (*pch_release)(void);
	void (*rst_pltrst)(bool assert);
	void (*rst_rtcrst)(bool assert);
	void (*i3c_mng_switch)(int owner);
};

const struct platform_gpio_ctrl_ops *get_platform_gpio_ctrl_ops(void);
