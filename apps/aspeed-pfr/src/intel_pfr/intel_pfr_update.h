/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>

int intel_pfr_update_verify(struct firmware_image *fw, struct hash_engine *hash, struct rsa_engine *rsa);

