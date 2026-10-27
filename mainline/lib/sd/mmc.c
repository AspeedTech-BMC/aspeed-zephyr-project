/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <aspeed/mmc.h>
#include <zephyr/logging/log.h>
#include <zephyr/sd/sd_spec.h>

#include "sd_ops.h"

#define MMC_SWITCH_BOOT_PART1                                                               \
	(0xFC000000 & (0U << 26)) + (0x03000000 & (0b11 << 24)) + (0x00FF0000 & (179U << 16)) + \
		(0x0000FF00 & (0x49 << 8)) + (0x000000F7 & (0U << 3)) + (0x00000000 & (3U << 0))

#define MMC_SWITCH_BOOT_PART2                                                               \
	(0xFC000000 & (0U << 26)) + (0x03000000 & (0b11 << 24)) + (0x00FF0000 & (179U << 16)) + \
		(0x0000FF00 & (0x52 << 8)) + (0x000000F7 & (0U << 3)) + (0x00000000 & (3U << 0))

LOG_MODULE_DECLARE(sd, CONFIG_SD_LOG_LEVEL);

int mmc_switch_part(struct sd_card *card, int part)
{
	int ret = 0;
	struct sdhc_command cmd = {0};
	uint32_t opcode;

	if (part == 1)
		opcode = MMC_SWITCH_BOOT_PART1;
	else if (part == 2)
		opcode = MMC_SWITCH_BOOT_PART2;
	else
		return -1;

	/* CMD6 selects the boot partition in EXT_CSD. */
	cmd.opcode = SD_SWITCH;
	cmd.arg = opcode;
	cmd.response_type = SD_RSP_TYPE_R1b;
	cmd.timeout_ms = CONFIG_SD_CMD_TIMEOUT;
	ret = sdhc_request(card->sdhc, &cmd, NULL);
	if (ret) {
		LOG_DBG("Error switching part: %d", ret);
		return ret;
	}
	ret = sdmmc_wait_ready(card);
	return ret;
}
