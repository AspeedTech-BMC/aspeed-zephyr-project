/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
typedef enum {
	PROV_FAIL = -1,
	PROV_DONE = 0,
	PROV_ROT_UPDATE = 1,
} PROV_STATUS;

PROV_STATUS cert_provision(void);
