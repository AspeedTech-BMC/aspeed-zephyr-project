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

#include "kernel.h"
#include "mctp.h"

#include <stdlib.h>
#include <string.h>
#include <zephyr.h>
#include <sys/crc.h>
#include <logging/log.h>
#include "mctp_utils.h"
#include "plat_mctp.h"
#include "i3c/hal_i3c.h"
#include "gpio/gpio_aspeed.h"
#include "Smbus_mailbox/Smbus_mailbox.h"
#include "AspeedStateMachine/AspeedStateMachine.h"

#include "mctp/mctp_base_protocol.h"

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
#define MCTP_DISCOVERY_NOTIFY_STACK_SIZE    4096
#define MCTP_I3C_MSG_RETRY_INTERVAL         12

#define MCTP_I3C_REGISTRATION_EID           0x1D
#define MCTP_DOE_REGISTRATION_CMD           0x4


static uint8_t i3c_data_in[256];
static uint8_t i3c_data_rx[256];
static uint8_t mctp_msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN];
static struct i3c_ibi_payload i3c_payload;
struct i3c_dev_desc mctp_i3c_slave;
const struct device *mctp_i3c_master;
struct k_thread mctp_i3c_discovery_notify_thread;
K_THREAD_STACK_DEFINE(mctp_i3c_discovery_notify_stack, MCTP_DISCOVERY_NOTIFY_STACK_SIZE);

static void mctp_i3c_req_timeout_callback(struct k_timer *tmr);
K_TIMER_DEFINE(mctp_i3c_req_timer, mctp_i3c_req_timeout_callback, NULL);
K_SEM_DEFINE(ibi_complete, 0, 1);
K_SEM_DEFINE(mctp_i3c_sem, 0, 1);

bool i3c_dev_attached = false;

extern mctp_i3c_dev i3c_dev;

void trigger_mctp_i3c_state_handler(void)
{
	k_sem_give(&mctp_i3c_sem);
}

void mctp_i3c_stop_discovery_notify(struct device_manager *mgr)
{
	int status;
	k_timer_stop(&mctp_i3c_req_timer);
	status = device_manager_update_device_state(mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM,
			DEVICE_MANAGER_EID_ANNOUNCEMENT);
	if (status != 0)
		LOG_ERR("update self device state failed");

	// Start eid announcement
	k_timer_start(&mctp_i3c_req_timer, K_SECONDS(2), K_NO_WAIT);
}

void mctp_i3c_pre_attestation(struct device_manager *mgr, int *duration)
{
	uint8_t provision_state = GetUfmStatusValue();
	if (!(provision_state & UFM_PROVISIONED) || !is_afm_ready()) {
		*duration = 300;
		return;
	}

	device_manager_update_device_state(mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM,
			DEVICE_MANAGER_ATTESTATION);
	*duration = 2;
}

int mctp_i3c_send_discovery_notify(mctp *mctp_instance, int *duration)
{
	struct mctp_interface_wrapper *mctp_wrapper = &mctp_instance->mctp_wrapper;
	struct mctp_interface *mctp_interface = &mctp_wrapper->mctp_interface;
	// { message_type, rq bit, command_code}
	uint8_t req_buf[3] = {MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, 0x81, 0x0d};

	mctp_interface_issue_request(mctp_interface, &mctp_instance->mctp_cmd_channel,
			BMC_I3C_SLAVE_ADDR, 0, req_buf, sizeof(req_buf), mctp_msg_buf,
			sizeof(mctp_msg_buf), 1);

	*duration = MCTP_I3C_MSG_RETRY_INTERVAL;

	return 0;
}

int mctp_i3c_send_eid_announcement(mctp *mctp_instance, int *duration)
{
	int status;
	struct mctp_interface_wrapper *mctp_wrapper = &mctp_instance->mctp_wrapper;
	struct mctp_interface *mctp_interface = &mctp_wrapper->mctp_interface;
	struct device_manager *device_mgr = mctp_interface->device_manager;
	uint8_t src_eid = device_manager_get_device_eid(device_mgr,
				DEVICE_MANAGER_SELF_DEVICE_NUM);
	uint8_t req_buf[14] = {MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, 0x80, 0x86, 0x80, 0x0a, 0x00,
		0x00, 0x00, 0x00, MCTP_DOE_REGISTRATION_CMD, 0x00, 0x00, 0x01, src_eid};

	if (get_i3c_mng_owner() == I3C_MNG_OWNER_BMC) {
		status = mctp_interface_issue_request(mctp_interface, &mctp_instance->mctp_cmd_channel,
				BMC_I3C_SLAVE_ADDR, MCTP_I3C_REGISTRATION_EID, req_buf,
				sizeof(req_buf), mctp_msg_buf, sizeof(mctp_msg_buf), 12000);
	} else {
		uint8_t dest_eid = device_manager_get_device_eid(device_mgr,
				DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM);
		status = mctp_interface_issue_request(mctp_interface, &mctp_instance->mctp_cmd_channel,
				CPU0_I3C_SLAVE_ADDR, dest_eid, req_buf,
				sizeof(req_buf), mctp_msg_buf, sizeof(mctp_msg_buf), 12000);
	}

	if (status == 0) {
		device_manager_update_device_state(device_mgr,
				DEVICE_MANAGER_SELF_DEVICE_NUM,
				DEVICE_MANAGER_PRE_ATTESTATION);
	}

	*duration = 2;

	return status;
}

void mctp_i3c_state_handler(void *a, void *b, void *c)
{
	mctp_i3c_dev *i3c_dev_p = &i3c_dev;
	mctp *mctp_instance = i3c_dev_p->mctp_inst;
	struct mctp_interface_wrapper *mctp_wrapper = &mctp_instance->mctp_wrapper;
	struct device_manager *device_mgr = mctp_wrapper->mctp_interface.device_manager;
	int dev_state;
	int duration = MCTP_I3C_MSG_RETRY_INTERVAL;

	while (1) {
		k_sem_take(&mctp_i3c_sem, K_FOREVER);
		dev_state = device_manager_get_device_state(device_mgr,
				DEVICE_MANAGER_SELF_DEVICE_NUM);
		if (dev_state == DEVICE_MANAGER_SEND_DISCOVERY_NOTIFY) {
			LOG_DBG("Send discovery notify");
			mctp_i3c_send_discovery_notify( mctp_instance, &duration);
		} else if (dev_state == DEVICE_MANAGER_EID_ANNOUNCEMENT) {
			LOG_DBG("Announce EID");
			mctp_i3c_send_eid_announcement(mctp_instance, &duration);
		}
#if defined(CONFIG_PFR_SPDM_ATTESTATION)
		else if (dev_state == DEVICE_MANAGER_PRE_ATTESTATION) {
			LOG_DBG("Pre-attestation");
			mctp_i3c_pre_attestation(device_mgr, &duration);
		} else if (dev_state == DEVICE_MANAGER_ATTESTATION) {
			LOG_DBG("Device Attestation start");
			// TODO: perform bmc/cpu0/cpu1 attestation via mctp i3c
			// attest_bmc_cpu0_and_cpu1();
			duration = 0;
		}
#endif
		else {
			duration = 0;
		}

		if (duration > 0 && i3c_dev_attached) {
			k_timer_start(&mctp_i3c_req_timer, K_SECONDS(duration), K_NO_WAIT);
		}
	}
}

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

	/* Workaround: extra bye appeded after PEC */
	uint8_t pec = 0x08 << 1;
	pec = crc8(&pec, 1, 0x07, 0x00, 0);
	pec = crc8(xfer.data.in, xfer.len, 0x07, pec, 0);
	if (pec != 0) {
		LOG_HEXDUMP_WRN(xfer.data.in, xfer.len, "I3C Workaround");
		xfer.len -= 1;
	}
	/* Workaround: extra bye appeded after PEC end */

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
	mctp_i3c_dev *i3c_dev_p = &i3c_dev;
	mctp *mctp_instance = i3c_dev_p->mctp_inst;
	struct mctp_interface_wrapper *mctp_wrapper = &mctp_instance->mctp_wrapper;
	struct device_manager *device_mgr = mctp_wrapper->mctp_interface.device_manager;

	if (!i3c_dev_attached)
		return 0;

	i3c_dev_attached = false;
	k_timer_stop(&mctp_i3c_req_timer);
	device_manager_update_device_state(device_mgr,
			DEVICE_MANAGER_SELF_DEVICE_NUM, DEVICE_MANAGER_SEND_DISCOVERY_NOTIFY);

	return i3c_aspeed_master_detach_device(mctp_i3c_master, &mctp_i3c_slave);
}

static void mctp_i3c_req_timeout_callback(struct k_timer *tmr)
{
	trigger_mctp_i3c_state_handler();
}

int mctp_i3c_attach_slave_dev(uint8_t slave_addr)
{
	LOG_INF("BMC booted, attaching I3C");
	switch_i3c_mng_owner(I3C_MNG_OWNER_BMC);
	mctp_i3c_master = device_get_binding("I3C_2");
	mctp_i3c_slave.info.static_addr = slave_addr;
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
	k_timer_start(&mctp_i3c_req_timer, K_SECONDS(12), K_NO_WAIT);

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
	mctp_instance->read_data = mctp_i3c_read;
	mctp_instance->write_data = mctp_i3c_write;
	k_tid_t mctp_i3c_state_tid = k_thread_create(&mctp_i3c_discovery_notify_thread,
			mctp_i3c_discovery_notify_stack,
			MCTP_DISCOVERY_NOTIFY_STACK_SIZE,
			mctp_i3c_state_handler,
			NULL, NULL, NULL, 5, 0, K_NO_WAIT);
	k_thread_name_set(mctp_i3c_state_tid, "MCTP I3C State Handler");
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
