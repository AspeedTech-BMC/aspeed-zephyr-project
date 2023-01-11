/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

/* Timer tick */
#define SPDM_REQ_EVT_TICK	BIT(2)
/* System in T0 */
#define SPDM_REQ_EVT_T0		BIT(1)
/* Enable attestation by UFM (Set in AspeedStateMachine::do_init once) */
#define SPDM_REQ_EVT_ENABLE	BIT(0)

int spdm_send_request(void *ctx, void *req_msg, void *rsp_msg);
void spdm_enable_attester();
void spdm_run_attester();
void spdm_stop_attester();
uint32_t spdm_get_attester();
