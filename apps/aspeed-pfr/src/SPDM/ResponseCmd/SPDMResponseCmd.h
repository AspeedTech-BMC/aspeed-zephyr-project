/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once
int spdm_handle_get_version(void *ctx, void *req, void *rsp);
int spdm_handle_get_capabilities(void *ctx, void *req, void *rsp);
int spdm_handle_negotiate_algorithms(void *ctx, void *req, void *rsp);
int spdm_handle_get_digests(void *ctx, void *req, void *rsp);
int spdm_handle_get_certificate(void *ctx, void *req, void *rsp);
int spdm_handle_challenge(void *ctx, void *req, void *rsp);
int spdm_handle_get_measurements(void *ctx, void *req, void *rsp);
