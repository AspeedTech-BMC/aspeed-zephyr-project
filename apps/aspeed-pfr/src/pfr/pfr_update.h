/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

extern int pfr_update_image(int image_type, void *AoData, void *EventContext);
void init_update_fw_manifest(struct firmware_image *fw);
int handle_update_image_action(int image_type, void *AoData, void *EventContext);

