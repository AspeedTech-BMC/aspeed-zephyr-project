/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#define ROT_PRELOAD_IMAGE_ID        0xa3

// 01h ROT Settings
#define ROT_SETTING_SPI_SRC     BIT(0)
#define ROT_SETTING_CS_SRC      BIT(1)
#define ROT_SETTING_FMC_SPI     BIT(2)
#define ROT_SETTING_MUX_INV     BIT(3)

// 03h ROT Status
#define ROT_FW_UPDATE_INPROGRESS    BIT(0)
#define ROT_FW_UPDATE_FAIl          BIT(1)
#define ROT_FW_CHECKSUM_FAIl        BIT(2)
#define ROT_FW_UPDATE_DONE          BIT(3)

typedef enum _SW_MAILBOX_RF_ADDRESS {
	RotWriteFifo = 0x7e,
	RotFwUpdateTrigger = 0x7f,
} SW_MAILBOX_ADDRESS;

typedef enum _ROT_CMD {
	RotCmdPreloadImgId = 0,
	RotCmdSetting,
	RotCmdCommand,
	RotCmdStatus,
	RotCmdStagingOffset0,
	RotCmdStagingOffset1,
	RotCmdStagingOffset2,
	RotCmdStagingOffset3,
	RotCmdImgSize0,
	RotCmdImgSize1,
	RotCmdImgSize2,
	RotCmdImgSize3,
	RotCmdChecksum0,
	RotCmdChecksum1,
	RotCmdChecksum2,
	RotCmdChecksum3,
} ROT_CMD;

union aspeed_event_data {
	/* Data in-place */
	uint32_t bit32;
	uint8_t bit8[4];

	/* Data somewhere else */
	uint8_t *ptr_u8;
	uint32_t *ptr_u32;
	void *ptr;
};

void SetRotCmdPreloadImgId(uint8_t preload_id);
void SetRotCmdStatus(uint8_t status);

void init_sw_mailbox(void);
