/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mctp.h"

#include <stdlib.h>
#include <string.h>
#include <zephyr.h>
#include <sys/crc.h>
#include <logging/log.h>
#include "mctp_utils.h"
#include "i3c/hal_i3c.h"

LOG_MODULE_REGISTER(mctp_i3c);

#if defined(CONFIG_I3C_SLAVE)
static uint16_t mctp_i3c_read_smq(void *mctp_p, void *msg_p)
{
	// Workaround
	// Add sleep here for preventing cpu stuck in while loop.
	k_msleep(1);

	CHECK_NULL_ARG_WITH_RETURN(mctp_p, MCTP_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(msg_p, MCTP_ERROR);

	struct cmd_packet *packet = (struct cmd_packet *)msg_p;
	uint8_t max_idx = ARRAY_SIZE(packet->data);
	int ret = 0;
	I3C_MSG i3c_msg;
	mctp *mctp_inst = (mctp *)mctp_p;
	i3c_msg.bus = mctp_inst->medium_conf.i3c_conf.bus;
	ret = i3c_smq_read(&i3c_msg);

	/** mctp rx keep polling, return length 0 directly if no data or invalid data **/
	if (ret <= 0) {
		memset(packet, 0, sizeof(struct cmd_packet));
		return 0;
	}

	packet->dest_addr = mctp_inst->medium_conf.i3c_conf.addr;
	packet->pkt_size = ret;
	packet->timeout_valid = 0;
	packet->pkt_timeout = 0;
	packet->state = CMD_VALID_PACKET;

	i3c_msg.rx_len = ret;
	if (ret > max_idx) {
		packet->state = CMD_OVERFLOW_PACKET;
		return MCTP_ERROR;
	}

	LOG_HEXDUMP_DBG(&i3c_msg.data[0], i3c_msg.rx_len, "mctp_i3c_read_smq msg dump");

	memcpy(packet->data, &i3c_msg.data[0], i3c_msg.rx_len);
	return MCTP_SUCCESS;
}

static uint16_t mctp_i3c_write_smq(void *mctp_p, void *msg_p)
{
	CHECK_NULL_ARG_WITH_RETURN(mctp_p, MCTP_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(msg_p, MCTP_ERROR);

	int ret;
	mctp *mctp_instance = (mctp *)mctp_p;
	mctp_tx_msg *tx_msg = (mctp_tx_msg *)msg_p;
	uint32_t len = tx_msg->len;
	I3C_MSG i3c_msg;

	if (tx_msg->ext_params.type != MCTP_MEDIUM_TYPE_I3C)
		return MCTP_ERROR;

	CHECK_NULL_ARG_WITH_RETURN(tx_msg->buf, MCTP_ERROR);

	if (!tx_msg->len)
		return MCTP_ERROR;

	i3c_msg.bus = mctp_instance->medium_conf.i3c_conf.bus;
	/** mctp package **/
	memcpy(&i3c_msg.data[0], tx_msg->buf, len);
	i3c_msg.tx_len = len;

	LOG_HEXDUMP_DBG(&i3c_msg.data[0], i3c_msg.tx_len, "mctp_i3c_write_smq msg dump");

	ret = i3c_smq_write(&i3c_msg);
	if (ret < 0) {
		LOG_ERR("mctp_i3c_write_smq write failed");
		return MCTP_ERROR;
	}
	return MCTP_SUCCESS;
}
#else
static uint8_t i3c_data_in[256];
static uint8_t i3c_data_rx[256];
static struct i3c_ibi_payload i3c_payload;
struct i3c_dev_desc mctp_i3c_slave;
const struct device *mctp_i3c_master;
static struct k_sem ibi_complete;
bool i3c_dev_attached = false;

static struct i3c_ibi_payload *ibi_write_requested(struct i3c_dev_desc *desc)
{
	i3c_payload.buf = i3c_data_rx;
	i3c_payload.size = 0;
	i3c_payload.max_payload_size = 256;

	return &i3c_payload;
}

static void ibi_write_done(struct i3c_dev_desc *desc)
{
	k_sem_give(&ibi_complete);
}

static struct i3c_ibi_callbacks i3c_ibi_mctp_callbacks = {
	.write_requested = ibi_write_requested,
	.write_done = ibi_write_done,
};

static uint16_t mctp_i3c_read(void *mctp_p, void *msg_p)
{
	struct cmd_packet *packet = (struct cmd_packet *)msg_p;
	mctp *mctp_inst = (mctp *)mctp_p;
	struct i3c_priv_xfer xfer;
	int ret;

	// read request from slave device.
	k_sem_take(&ibi_complete, K_FOREVER);
	memset(i3c_data_in, 0, sizeof(i3c_data_in));

	xfer.rnw = 1;
	xfer.len = CMD_MAX_PACKET_SIZE;
	xfer.data.in = i3c_data_in;
	ret = i3c_master_priv_xfer(&mctp_i3c_slave, &xfer, 1);

	packet->dest_addr = mctp_inst->medium_conf.i3c_conf.addr;
	packet->pkt_size = xfer.len;
	packet->timeout_valid = 0;
	packet->pkt_timeout = 0;
	packet->state = CMD_VALID_PACKET;
	memcpy(packet->data, xfer.data.in, xfer.len);

	return 0;
}

static uint16_t mctp_i3c_write(void *mctp_p, void *msg_p)
{
	mctp_tx_msg *tx_msg = (mctp_tx_msg *)msg_p;
	struct i3c_priv_xfer xfer;
	int ret;

	if (tx_msg->ext_params.type != MCTP_MEDIUM_TYPE_I3C)
		return MCTP_ERROR;

	CHECK_NULL_ARG_WITH_RETURN(tx_msg->buf, MCTP_ERROR);

	if (!tx_msg->len)
		return MCTP_ERROR;

	xfer.rnw = 0;
	xfer.len = tx_msg->len;
	xfer.data.out = tx_msg->buf;
	ret = i3c_master_priv_xfer(&mctp_i3c_slave, &xfer, 1);
	if (ret) {
		LOG_ERR("mctp_i3c_write failed");
		return MCTP_ERROR;
	}

	return MCTP_SUCCESS;
}

int mctp_i3c_detach_slave_dev(void)
{
	if (!i3c_dev_attached)
		return 0;

	i3c_dev_attached = false;

	return i3c_aspeed_master_detach_device(mctp_i3c_master, &mctp_i3c_slave);
}

int mctp_i3c_attach_slave_dev(void)
{
	LOG_INF("BMC booted, attaching I3C");
	mctp_i3c_master = device_get_binding("I3C_2");
	mctp_i3c_slave.info.static_addr = 0x08;
	mctp_i3c_slave.info.assigned_dynamic_addr = mctp_i3c_slave.info.static_addr;
	mctp_i3c_slave.info.i2c_mode = 0;
	if (i3c_aspeed_master_attach_device(mctp_i3c_master, &mctp_i3c_slave))
		goto error;

	i3c_dev_attached = true;

	if (i3c_master_send_rstdaa(mctp_i3c_master))
		goto error;

	if (i3c_master_send_rstdaa(mctp_i3c_master))
		goto error;

	if (i3c_master_send_aasa(mctp_i3c_master))
		goto error;

	if (i3c_master_send_getpid(mctp_i3c_master, mctp_i3c_slave.info.dynamic_addr, &mctp_i3c_slave.info.pid))
		goto error;

	if (i3c_master_send_getbcr(mctp_i3c_master, mctp_i3c_slave.info.dynamic_addr, &mctp_i3c_slave.info.bcr))
		goto error;

	if (i3c_master_request_ibi(&mctp_i3c_slave, &i3c_ibi_mctp_callbacks))
		goto error;

	if (i3c_master_enable_ibi(&mctp_i3c_slave))
		goto error;


	LOG_INF("I3C slave device attached");

	return 0;
error:
	LOG_ERR("I3C slave device attach failed");
	return -1;
}
#endif

uint8_t mctp_i3c_init(mctp *mctp_instance, mctp_medium_conf medium_conf)
{
	CHECK_NULL_ARG_WITH_RETURN(mctp_instance, MCTP_ERROR);

	mctp_instance->medium_conf = medium_conf;
#if defined(CONFIG_I3C_SLAVE)
	mctp_instance->read_data = mctp_i3c_read_smq;
	mctp_instance->write_data = mctp_i3c_write_smq;
#else
	k_sem_init(&ibi_complete, 0, 1);
	mctp_instance->read_data = mctp_i3c_read;
	mctp_instance->write_data = mctp_i3c_write;
#endif

	return MCTP_SUCCESS;
}

uint8_t mctp_i3c_deinit(mctp *mctp_instance)
{
	CHECK_NULL_ARG_WITH_RETURN(mctp_instance, MCTP_ERROR);

	mctp_instance->read_data = NULL;
	mctp_instance->write_data = NULL;
	memset(&mctp_instance->medium_conf, 0, sizeof(mctp_instance->medium_conf));
	return MCTP_SUCCESS;
}
