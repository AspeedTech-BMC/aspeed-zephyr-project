/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <recovery/recovery_image.h>
#pragma once

int recover_image(void *AoData, void *EventContext);
void init_recovery_manifest(struct recovery_image *image);
