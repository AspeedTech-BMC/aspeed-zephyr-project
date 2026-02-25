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
#include "libutil.h"
#include <zephyr/logging/log.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/kernel.h>

#ifndef IANA_ID
#define IANA_ID 0xA59EED // Dummy ASPEED IANA ID
#endif

LOG_MODULE_DECLARE(pldm, LOG_LEVEL_DBG);

uint8_t check_iana(const uint8_t *iana)
{
	CHECK_NULL_ARG_WITH_RETURN(iana, PLDM_ERROR);

	for (uint8_t i = 0; i < IANA_LEN; i++) {
		if (iana[i] != ((IANA_ID >> (i * 8)) & 0xFF))
			return PLDM_ERROR;
	}

	return PLDM_SUCCESS;
}

uint8_t set_iana(uint8_t *buf, uint8_t buf_len)
{
	CHECK_NULL_ARG_WITH_RETURN(buf, PLDM_ERROR);
	CHECK_ARG_WITH_RETURN(buf_len < IANA_LEN, PLDM_ERROR);

	for (uint8_t i = 0; i < IANA_LEN; i++)
		buf[i] = (IANA_ID >> (i * 8)) & 0xFF;

	return PLDM_SUCCESS;
}

static uint8_t cmd_echo(void *mctp_inst, uint8_t *buf, uint16_t len, uint8_t instance_id,
			uint8_t *resp, uint16_t *resp_len, void *ext_params)
{
	CHECK_NULL_ARG_WITH_RETURN(mctp_inst, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(buf, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(resp, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(resp_len, PLDM_ERROR);
	CHECK_NULL_ARG_WITH_RETURN(ext_params, PLDM_ERROR);

	struct _cmd_echo_req *req_p = (struct _cmd_echo_req *)buf;
	struct _cmd_echo_resp *resp_p = (struct _cmd_echo_resp *)resp;

	if (check_iana(req_p->iana) == PLDM_ERROR) {
		resp_p->completion_code = PLDM_ERROR_INVALID_DATA;
		return PLDM_SUCCESS;
	}

	set_iana(resp_p->iana, sizeof(resp_p->iana));
	resp_p->completion_code = PLDM_SUCCESS;
	memcpy(&resp_p->first_data, &req_p->first_data, len);
	*resp_len = len + 1;
	return PLDM_SUCCESS;
}


static pldm_cmd_handler pldm_oem_cmd_tbl[] = { { PLDM_OEM_CMD_ECHO, cmd_echo },
					       };

uint8_t pldm_oem_handler_query(uint8_t code, void **ret_fn)
{
	if (!ret_fn)
		return PLDM_ERROR;

	pldm_cmd_proc_fn fn = NULL;
	uint8_t i;

	for (i = 0; i < ARRAY_SIZE(pldm_oem_cmd_tbl); i++) {
		if (pldm_oem_cmd_tbl[i].cmd_code == code) {
			fn = pldm_oem_cmd_tbl[i].fn;
			break;
		}
	}

	*ret_fn = (void *)fn;
	return fn ? PLDM_SUCCESS : PLDM_ERROR;
}
