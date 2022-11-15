/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <zephyr.h>
#include "sw_mailbox/sw_mailbox.h"

#define PAGE_SIZE 4096

void configure_staging_source(union aspeed_event_data *data);
void set_fw_staging_source(union aspeed_event_data *data);
void set_fw_image_size(union aspeed_event_data *data);
void set_fw_image_checksum(union aspeed_event_data *data);
int rot_fw_update(void);

