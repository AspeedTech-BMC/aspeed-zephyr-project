/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ASPEED_MMC_H_
#define ASPEED_MMC_H_

#include <zephyr/sd/mmc.h>

int mmc_switch_part(struct sd_card *card, int part);

#endif /* ASPEED_MMC_H_ */
