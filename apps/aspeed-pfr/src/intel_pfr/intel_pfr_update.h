/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef INTEL_PFR_UPDATE_H_
#define INTEL_PFR_UPDATE_H_

#include <stdint.h>

int intel_pfr_update_verify (struct firmware_image *fw, struct hash_engine *hash, struct rsa_engine *rsa);

#endif /*INTEL_PFR_UPDATE_H_*/
