/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <init.h>
#include <zephyr.h>
#include <logging/log.h>
#include <drivers/gpio.h>

#define LOG_MODULE_NAME board
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

static int ast1060_prot_post_init(const struct device *arg)
{
	return 0;
}

static int ast1060_prot_init(const struct device *arg)
{
	return 0;
}

SYS_INIT(ast1060_prot_post_init, POST_KERNEL, 60);
SYS_INIT(ast1060_prot_init, APPLICATION, 0);
