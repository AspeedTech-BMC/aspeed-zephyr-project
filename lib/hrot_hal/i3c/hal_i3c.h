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

#ifndef HAL_I3C_H
#define HAL_I3C_H

#include <zephyr.h>
#include <drivers/i3c/i3c.h>

#define CHECK_NULL_ARG_WITH_RETURN(arg_ptr, ret_val)                                               \
	if (arg_ptr == NULL) {                                                                     \
		LOG_DBG("Parameter \"" #arg_ptr "\" passed in as NULL");                           \
		return ret_val;                                                                    \
	}

#if DT_NODE_HAS_STATUS(DT_NODELABEL(i3c0), okay)
#define DEV_I3C_0
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(i3c1), okay)
#define DEV_I3C_1
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(i3c2), okay)
#define DEV_I3C_2
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(i3c3), okay)
#define DEV_I3C_3
#endif

#if DT_NODE_EXISTS(DT_NODELABEL(i3c0_smq))
#define DEV_I3CSMQ_0
#endif

#if DT_NODE_EXISTS(DT_NODELABEL(i3c1_smq))
#define DEV_I3CSMQ_1
#endif

#if DT_NODE_EXISTS(DT_NODELABEL(i3c2_smq))
#define DEV_I3CSMQ_2
#endif

#if DT_NODE_EXISTS(DT_NODELABEL(i3c3_smq))
#define DEV_I3CSMQ_3
#endif

#define DEV_I3C(n) DEV_I3C_##n
#define DEV_I3CSMQ(n) DEV_I3CSMQ_##n

#define I3C_MAX_NUM 4
#define I3C_MAX_DATA_SIZE 256

enum I3C_WRITE_READ_CMD {
	I3C_WRITE_CMD = 0,
	I3C_READ_CMD,
};

typedef struct _I3C_MSG_ {
	uint8_t bus;
	uint8_t target_addr;
	uint8_t tx_len;
	uint8_t rx_len;
	uint8_t data[I3C_MAX_DATA_SIZE];
} I3C_MSG;

void util_init_i3c(void);
int i3c_smq_read(I3C_MSG *msg);
int i3c_smq_write(I3C_MSG *msg);

#endif
