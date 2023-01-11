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

uint8_t mctp_i3c_init(mctp *mctp_instance, mctp_medium_conf medium_conf)
{
	CHECK_NULL_ARG_WITH_RETURN(mctp_instance, MCTP_ERROR);

	mctp_instance->medium_conf = medium_conf;
	mctp_instance->read_data = mctp_i3c_read_smq;
	mctp_instance->write_data = mctp_i3c_write_smq;

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
