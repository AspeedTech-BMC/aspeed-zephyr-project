/*
 * Copyright (c) 2023 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <device.h>
#include <drivers/i2c.h>
#include "pfr/pfr_common.h"

#define SCM_BOARD_ID_DEFAULT             0x29

/* Intel RSU control registers */
#define INTEL_RSU_REG_DEV_TYPE           0x00
#define INTEL_RSU_REG_SYS_RESET          0x02
// Support Mode
#define INTEL_RSU_REG_SUPPORT_MODE       0x04
#define RSU_SUPPORT_MODE_BYTE            BIT(0)
#define RSU_SUPPORT_MODE_WORD            BIT(1)
#define RSU_SUPPORT_MODE_CRC             BIT(2)
#define RSU_SUPPORT_MODE_DEFAULT         (RSU_SUPPORT_MODE_WORD | RSU_SUPPORT_MODE_CRC)

#define INTEL_RSU_REG_DEV_ADDR           0x06
#define INTEL_RSU_REG_IMG_CRC            0x08

// Status of CPLD
#define INTEL_RSU_REG_CFG_STS            0x32
#define RSU_CFG_STS_FALLBACK_EVENT       BIT(0)
#define RSU_CFG_STS_CFM0_LOADED          BIT(1)
#define RSU_CFG_STS_CFM1_LOADED          BIT(2)

#define INTEL_RSU_REG_FLASH_STS          0x34

// Status Register
#define INTEL_RSU_REG_STATUS             0x36
#define RSU_STATUS_APP_ERROR             BIT(0)
#define RSU_STATUS_RESERVED              BIT(1)
#define RSU_STATUS_FLASH_ERROR           BIT(2)
#define RSU_STATUS_FLASH_BUSY            BIT(3)
#define RSU_STATUS_LOCK_PIN              BIT(4)
#define RSU_STATUS_LOCK_REG              BIT(5)

#define INTEL_RSU_REG_LOCK               0x38
#define INTEL_RSU_REG_FLASH_ADDR_H       0x7a
#define INTEL_RSU_REG_FLASH_ADDR_L       0x7c
#define INTEL_RSU_REG_FLASH_OP_LEN       0x7e

// Intel RSU Register Command
#define INTEL_RSU_REG_CMD                0x80
#define RSU_LOAD_CFM0                    BIT(0)
#define RSU_LOAD_CFM1                    BIT(1)
#define RSU_FLASH_ERASE                  BIT(2)
#define RSU_FLASH_WRITE                  BIT(3)
// For Debug purpose
#define RSU_FLASH_READ                   BIT(4)


#define INTEL_RSU_REG_IP_REV             0x82
#define INTEL_RSU_REG_FW_REV             0x84

// Primary Error Status
#define INTEL_RSU_REG_ERR_STS            0x86
#define RSU_ERR_APP_ERROR                BIT(0)
#define RSU_ERR_CRC_ERROR                BIT(1)
#define RSU_ERR_FLASH_ERROR              BIT(2)
#define RSU_ERR_FLASH_BUSY               BIT(3)
#define RSU_ERROR                        (RSU_ERR_APP_ERROR | RSU_ERR_CRC_ERROR)

// For Debug purpose
#define INTEL_RSU_REG_FLASH_RD_MEM_H     0x8a
#define INTEL_RSU_REG_FLASH_RD_MEM_L     0x88

// Register 0x86 RSU Primary Error


enum RSU_TYPE {
	CPU_CPLD = 0,
	SCM_CPLD,
	DEBUG_CPLD,
	MAX_RSU_TYPE,
};

enum RSU_REG_TYPE {
	RSU_CTRL_REG = 0,
	RSU_DATA_REG,
};

enum RSU_MSG_TYPE {
	RSU_CTRL_WRITE_MSG = 0,
	RSU_CTRL_READ_MSG,
	RSU_DATA_WRITE_MSG,
};

#pragma pack(1)
typedef struct {
	uint8_t write_addr;
	uint8_t reg_type;
	uint8_t reg_addr;
	uint8_t zero;
	uint8_t one;
	uint8_t write_data[2];
	uint8_t crc;
} RSU_CTRL_REG_WRITE;

typedef struct {
	uint8_t write_addr;
	uint8_t reg_type;
	uint8_t reg_addr;
	uint8_t read_addr;
	uint8_t read_data[2];
} RSU_CTRL_REG_READ;

typedef struct {
	uint8_t write_addr;
	uint8_t reg_type;
	uint8_t ram_addr;
	uint8_t zero;
	uint8_t word_len;
} RSU_DATA_REG_WRITE;
#pragma pack()

int intel_rsu_read_ctrl_reg(uint8_t rsu_type, uint8_t reg, uint16_t *val);
int intel_rsu_write_ctrl_reg(uint8_t rsu_type, uint8_t reg, uint8_t wdata_h, uint8_t wdata_l);
int intel_rsu_write_data_reg(uint8_t rsu_type, uint8_t *buf, uint8_t buf_len);
int intel_rsu_dump_cpld_flash(uint8_t rsu_type, uint32_t addr, uint32_t dw_len);
int intel_rsu_hide_rsu(void);
int intel_rsu_unhide_rsu(void);
int intel_rsu_get_support_mode(uint8_t rsu_type, uint16_t mode);
int intel_rsu_get_lock_reg(uint8_t rsu_type);
int intel_rsu_handshake(uint8_t rsu_type);
int intel_rsu_load_fw(uint8_t rsu_type, uint8_t image_load_bit);
int intel_rsu_check_fw_loaded(uint8_t rsu_type, uint16_t image_loaded_bit);
int intel_rsu_get_scm_board_id(void);
int intel_rsu_perform_update(struct pfr_manifest *manifest, uint8_t rsu_type, uint32_t up_addr);
