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

#include "hal_i3c.h"

#include <device.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zephyr.h>
#include <logging/log.h>

LOG_MODULE_REGISTER(hal_i3c);

static const struct device *dev_i3c[I3C_MAX_NUM];
static const struct device *dev_i3c_smq[I3C_MAX_NUM];
static struct i3c_dev_desc i3c_desc_table[I3C_MAX_NUM];
static int i3c_desc_count = 0;

int i3c_slave_mqueue_read(const struct device *dev, uint8_t *dest, int budget);
int i3c_slave_mqueue_write(const struct device *dev, uint8_t *src, int size);

/**
 * @brief api to read i3c message from target message queue
 *
 * @param msg i3c message structure
 * @return ret: return the data size
 */
int i3c_smq_read(I3C_MSG *msg)
{
	CHECK_NULL_ARG_WITH_RETURN(msg, -EINVAL);

	if (!dev_i3c[msg->bus]) {
		LOG_ERR("[%s] bus%u did not define\n", __func__, msg->bus);
		return -ENODEV;
	}

	msg->rx_len =
		i3c_slave_mqueue_read(dev_i3c_smq[msg->bus], &msg->data[0], I3C_MAX_DATA_SIZE);
	if (msg->rx_len == 0) {
		return -ENODATA;
	}

	return msg->rx_len;
}

/**
 * @brief api to write i3c message to target message queue
 *
 * @param msg i3c message structure
 * @return 0: api to write i3c message to target message queue
 */
int i3c_smq_write(I3C_MSG *msg)
{
	CHECK_NULL_ARG_WITH_RETURN(msg, -EINVAL);

	int ret;
	if (!dev_i3c[msg->bus]) {
		LOG_ERR("[%s] bus%u did not define\n", __func__, msg->bus);
		return -ENODEV;
	}

	ret = i3c_slave_mqueue_write(dev_i3c_smq[msg->bus], &msg->data[0], msg->tx_len);
	return ret;
}

void util_init_i3c(void)
{
#ifdef DEV_I3C_0
	dev_i3c[0] = device_get_binding("I3C_0");
#endif
#ifdef DEV_I3C_1
	dev_i3c[1] = device_get_binding("I3C_1");
#endif
#ifdef DEV_I3C_2
	dev_i3c[2] = device_get_binding("I3C_2");
#endif
#ifdef DEV_I3C_3
	dev_i3c[3] = device_get_binding("I3C_3");
#endif

#ifdef DEV_I3CSMQ_0
	dev_i3c_smq[0] = device_get_binding("I3C_SMQ_0");
#endif
#ifdef DEV_I3CSMQ_1
	dev_i3c_smq[1] = device_get_binding("I3C_SMQ_1");
#endif
#ifdef DEV_I3CSMQ_2
	dev_i3c_smq[2] = device_get_binding("I3C_SMQ_2");
#endif
#ifdef DEV_I3CSMQ_3
	dev_i3c_smq[3] = device_get_binding("I3C_SMQ_3");
#endif
}
