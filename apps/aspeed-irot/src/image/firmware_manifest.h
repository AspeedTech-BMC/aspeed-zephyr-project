/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stddef.h>

#include <zephyr/device.h>

#pragma once

struct firmware_manifest_handler {
	void *manifest_context;
	int (*verify_manifest)(const struct device *man_dev, const struct device *fmc_dev, size_t offset);
	int (*load_image)();
};
