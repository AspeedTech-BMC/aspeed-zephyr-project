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

#include "pldm.h"
#include <zephyr/logging/log.h>
#include <string.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/slist.h>
#include <zephyr/sys/util.h>
#include <zephyr/kernel.h>
#include "libutil.h"

LOG_MODULE_DECLARE(pldm, LOG_LEVEL_DBG);

#define PLDM_VERSION_BASE 0xF1F1F000u
#define PLDM_VERSION_FW_UPDATE 0xF1F3F000u

static void advertise_fw_update_exchange_commands(uint8_t *commands)
{
	/* These commands are initiated by the firmware device during download.
	 * They have no inbound handler, but DSP0267 discovery expects the firmware
	 * device to advertise the complete update exchange.
	 */
	static const uint8_t fd_commands[] = {
		PLDM_FW_UPDATE_CMD_CODE_REQUEST_FIRMWARE_DATA,
		PLDM_FW_UPDATE_CMD_CODE_TRANSFER_COMPLETE,
		PLDM_FW_UPDATE_CMD_CODE_VERIFY_COMPLETE,
		PLDM_FW_UPDATE_CMD_CODE_APPLY_COMPLETE,
		PLDM_FW_UPDATE_CMD_CODE_CANCEL_UPDATE_COMPONENT,
	};

	for (size_t i = 0; i < ARRAY_SIZE(fd_commands); ++i)
		commands[fd_commands[i] / 8] |= BIT(fd_commands[i] % 8);
}

__weak uint8_t plat_pldm_get_tid()
{
	return DEFAULT_TID;
}

uint8_t set_tid(void *mctp_inst, uint8_t *buf, uint16_t len, uint8_t instance_id, uint8_t *resp,
		uint16_t *resp_len, void *ext_params)
{
	if (!mctp_inst || !buf || !resp || !resp_len)
		return PLDM_ERROR;

	struct _set_tid_req *req_p = (struct _set_tid_req *)buf;
	struct _set_tid_resp *resp_p = (struct _set_tid_resp *)resp;

	*resp_len = 1;
	resp_p->completion_code =
		(sizeof(*req_p) != len) ? PLDM_ERROR_INVALID_LENGTH : PLDM_SUCCESS;
	return PLDM_SUCCESS;
}

uint8_t get_tid(void *mctp_inst, uint8_t *buf, uint16_t len, uint8_t instance_id, uint8_t *resp,
		uint16_t *resp_len, void *ext_params)
{
	if (!mctp_inst || !buf || !resp || !resp_len)
		return PLDM_ERROR;

	struct _get_tid_resp *p = (struct _get_tid_resp *)resp;
	p->completion_code = PLDM_SUCCESS;
	p->tid = plat_pldm_get_tid();
	*resp_len = sizeof(*p);
	return PLDM_SUCCESS;
}

uint8_t get_pldm_types(void *mctp_inst, uint8_t *buf, uint16_t len, uint8_t instance_id,
		       uint8_t *resp, uint16_t *resp_len, void *ext_params)
{
	CHECK_NULL_ARG_WITH_RETURN(mctp_inst, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(buf, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(resp, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(resp_len, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(ext_params, PLDM_ERROR);

	struct _get_pldm_types_resp *p = (struct _get_pldm_types_resp *)resp;

	if (len > 0) {
		p->completion_code = PLDM_ERROR_INVALID_LENGTH;
		*resp_len = 1;
		return PLDM_SUCCESS;
	}

	uint8_t rc = get_supported_pldm_type(p->pldm_types, sizeof(p->pldm_types));

	*resp_len = (rc == PLDM_SUCCESS) ? sizeof(*p) : 1;
	p->completion_code = rc;
	return PLDM_SUCCESS;
}

uint8_t get_pldm_version(void *mctp_inst, uint8_t *buf, uint16_t len, uint8_t instance_id,
			 uint8_t *resp, uint16_t *resp_len, void *ext_params)
{
	struct _get_pldm_version_req *req = (struct _get_pldm_version_req *)buf;
	struct _get_pldm_version_resp *response = (struct _get_pldm_version_resp *)resp;

	CHECK_NULL_ARG_WITH_RETURN(mctp_inst, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(buf, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(resp, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(resp_len, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(ext_params, PLDM_ERROR);

	*resp_len = 1;
	if (len != sizeof(*req)) {
		response->completion_code = PLDM_ERROR_INVALID_LENGTH;
		return PLDM_SUCCESS;
	}
	if (req->data_transfer_handle != 0) {
		response->completion_code = 0x80; /* InvalidDataTransferHandle */
		return PLDM_SUCCESS;
	}
	if (req->transfer_op_flag != 1) { /* GetFirstPart */
		response->completion_code = 0x81; /* InvalidTransferOperationFlag */
		return PLDM_SUCCESS;
	}

	switch (req->pldm_type) {
	case PLDM_TYPE_BASE:
		response->version = PLDM_VERSION_BASE;
		break;
	case PLDM_TYPE_FW_UPDATE:
		response->version = PLDM_VERSION_FW_UPDATE;
		break;
	default:
		response->completion_code = INVALID_PLDM_TYPE_IN_REQUEST_DATA;
		return PLDM_SUCCESS;
	}

	response->completion_code = PLDM_SUCCESS;
	response->next_transfer_handle = 0;
	response->transfer_resp_flag = PLDM_START_AND_END;
	*resp_len = sizeof(*response);
	return PLDM_SUCCESS;
}

uint8_t get_pldm_commands(void *mctp_inst, uint8_t *buf, uint16_t len, uint8_t instance_id,
			  uint8_t *resp, uint16_t *resp_len, void *ext_params)
{
	CHECK_NULL_ARG_WITH_RETURN(mctp_inst, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(buf, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(resp, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(resp_len, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(ext_params, PLDM_ERROR);

	struct _get_pldm_commands_req *req_p = (struct _get_pldm_commands_req *)buf;
	struct _get_pldm_commands_resp *resp_p = (struct _get_pldm_commands_resp *)resp;

	if (len != sizeof(struct _get_pldm_commands_req)) {
		resp_p->completion_code = PLDM_ERROR_INVALID_LENGTH;
		*resp_len = 1;
		return PLDM_SUCCESS;
	}

	uint8_t rc = get_supported_pldm_commands(req_p->type, resp_p->pldm_commands,
						 sizeof(resp_p->pldm_commands));
	if ((rc == PLDM_SUCCESS) && (req_p->type == PLDM_TYPE_FW_UPDATE))
		advertise_fw_update_exchange_commands(resp_p->pldm_commands);

	switch (rc) {
	case PLDM_ERROR_INVALID_PLDM_TYPE:
		resp_p->completion_code = INVALID_PLDM_TYPE_IN_REQUEST_DATA;
		break;

	case PLDM_ERROR:
	case PLDM_ERROR_INVALID_LENGTH:
		resp_p->completion_code = PLDM_ERROR;
		break;

	case PLDM_SUCCESS:
		resp_p->completion_code = PLDM_SUCCESS;
		break;

	default:
		resp_p->completion_code = PLDM_ERROR;
		break;
	}

	*resp_len = sizeof(*resp_p);
	return rc;
}

static pldm_cmd_handler pldm_base_cmd_tbl[] = {
	{ PLDM_BASE_CMD_CODE_SETTID, set_tid },
	{ PLDM_BASE_CMD_CODE_GETTID, get_tid },
	{ PLDM_BASE_CMD_CODE_GET_PLDM_VER, get_pldm_version },
	{ PLDM_BASE_CMD_CODE_GET_PLDM_TYPE, get_pldm_types },
	{ PLDM_BASE_CMD_CODE_GET_PLDM_CMDS, get_pldm_commands },
};

uint8_t pldm_base_handler_query(uint8_t code, void **ret_fn)
{
	if (!ret_fn)
		return PLDM_ERROR;

	pldm_cmd_proc_fn fn = NULL;
	uint8_t i;

	for (i = 0; i < ARRAY_SIZE(pldm_base_cmd_tbl); i++) {
		if (pldm_base_cmd_tbl[i].cmd_code == code) {
			fn = pldm_base_cmd_tbl[i].fn;
			break;
		}
	}

	*ret_fn = (void *)fn;
	return fn ? PLDM_SUCCESS : PLDM_ERROR;
}
