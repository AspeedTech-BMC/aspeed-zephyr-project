/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <zephyr/drivers/i3c.h>
#include <zephyr/drivers/i3c/ccc.h>
#include <zephyr/drivers/i3c/ibi.h>

/* Controller-driver adaptation boundary. */
struct mctp_i3c_backend_ops {
	size_t (*received_len)(const struct i3c_msg *msg);
	int (*configure_ibi)(struct i3c_device_desc *desc,
			     i3c_target_ibi_cb_t callback,
			     struct i3c_ccc_mrl *mrl);
	bool (*ibi_is_data_ready)(const struct i3c_ibi_payload *payload);
	void (*reset_dynamic_addr)(struct i3c_device_desc *desc);
};

/* CMake selects exactly one immutable backend implementation. */
extern const struct mctp_i3c_backend_ops mctp_i3c_backend;
