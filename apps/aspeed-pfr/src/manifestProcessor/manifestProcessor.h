/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ZEPHYR_ASPEED_PFR_SRC_MANIFESTPROCESSOR_MANIFESTPROCESSOR_H_
#define ZEPHYR_ASPEED_PFR_SRC_MANIFESTPROCESSOR_MANIFESTPROCESSOR_H_

#include <zephyr.h>

int initializeManifestProcessor(void);
int processPfmFlashManifest(void);

#endif /* ZEPHYR_ASPEED_PFR_SRC_MANIFESTPROCESSOR_MANIFESTPROCESSOR_H_ */
