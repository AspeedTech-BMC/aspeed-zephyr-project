/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>

#include "mctp_i3c_backend.h"

static size_t ast1060_received_len(const struct i3c_msg *msg)
{
	return msg->len;
}

static int ast1060_configure_ibi(struct i3c_device_desc *desc,
				i3c_target_ibi_cb_t callback,
				struct i3c_ccc_mrl *mrl)
{
	desc->ibi_cb = callback;
	if (i3c_ibi_enable(desc))
		return -EIO;

	i3c_ccc_do_setmrl(desc, mrl);
	return 0;
}

static bool ast1060_ibi_is_data_ready(const struct i3c_ibi_payload *payload)
{
	return payload && payload->payload_len;
}

static void ast1060_reset_dynamic_addr(struct i3c_device_desc *desc)
{
	desc->dynamic_addr = 0;
}

const struct mctp_i3c_backend_ops mctp_i3c_backend = {
	.received_len = ast1060_received_len,
	.configure_ibi = ast1060_configure_ibi,
	.ibi_is_data_ready = ast1060_ibi_is_data_ready,
	.reset_dynamic_addr = ast1060_reset_dynamic_addr,
};
