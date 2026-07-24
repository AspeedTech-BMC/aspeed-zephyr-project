/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <zephyr/sys/util.h>

#include "mctp_i3c_backend.h"

static size_t mipi_received_len(const struct i3c_msg *msg)
{
	return msg->num_xfer;
}

static int mipi_configure_ibi(struct i3c_device_desc *desc,
			      i3c_target_ibi_cb_t callback,
			      struct i3c_ccc_mrl *mrl)
{
	int ret;

	ret = i3c_ibi_disable(desc);
	if (ret && ret != -ENODEV)
		return ret;

	desc->ibi_cb = callback;
	desc->data_length.mrl = mrl->len;
	desc->data_length.max_ibi = mrl->ibi_len;

	ret = i3c_ccc_do_setmrl(desc, mrl);
	if (ret)
		return ret;

	ret = i3c_ibi_enable(desc);
	return ret == -EALREADY ? 0 : ret;
}

static bool mipi_ibi_is_data_ready(const struct i3c_ibi_payload *payload)
{
	/* MIPI HCI reports a status-only IBI with a NULL payload. */
	ARG_UNUSED(payload);
	return true;
}

static void mipi_reset_dynamic_addr(struct i3c_device_desc *desc)
{
	/*
	 * MIPI HCI needs the old address to release the address slot and
	 * relocate the DAT entry during the next DAA.
	 */
	ARG_UNUSED(desc);
}

const struct mctp_i3c_backend_ops mctp_i3c_backend = {
	.received_len = mipi_received_len,
	.configure_ibi = mipi_configure_ibi,
	.ibi_is_data_ready = mipi_ibi_is_data_ready,
	.reset_dynamic_addr = mipi_reset_dynamic_addr,
};
