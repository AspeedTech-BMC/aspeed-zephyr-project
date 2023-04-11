#!/usr/bin/env python3

"""
Copyright (c) 2023 ASPEED Technology Inc.

SPDX-License-Identifier: MIT
"""

# Permitted SPI commands
SPI_CMD_PAGE_PROGRAM           = 0x02;
SPI_CMD_READ_SLOW              = 0x03;
SPI_CMD_READ_SLOW_4BYTE        = 0x13;
SPI_CMD_WRITE_DISABLE          = 0x04;
SPI_CMD_READ_STATUS_REG        = 0x05;
SPI_CMD_WRITE_ENABLE           = 0x06;
SPI_CMD_READ_FAST              = 0x0B;
SPI_CMD_4B_READ_FAST           = 0x0C;
SPI_CMD_PAGE_PROGRAM_4BYTE     = 0x12;
SPI_CMD_ERASE_4K               = 0x20;
SPI_CMD_DUAL_OUT_FAST_RD       = 0x3B;
SPI_CMD_DUAL_OUT_FAST_RD_4BYTE = 0x3C;
SPI_CMD_READ_SFDP              = 0x5A;
SPI_CMD_QUAD_OUT_FAST_RD       = 0x6B;
SPI_CMD_4B_QUAD_OUT_FAST_RD    = 0x6C;
SPI_READ_FLAG_STATUS_REGISTER  = 0x70;
SPI_CMD_READ_ID                = 0x9F;
SPI_CMD_ENTER_4B_ADDR_MODE     = 0xB7;
SPI_CMD_DUAL_INOUT_FAST_RD     = 0xBB;
SPI_CMD_CLEAR_FLR              = 0x50;
SPI_CMD_SECTOR_ERASE           = 0xD8;
SPI_CMD_4B_SECTOR_ERASE        = 0xDC;
SPI_CMD_ENTER_DPD              = 0xB9;

# 1-byte SPI commands that must be blocked before the command completes
# The purpose of enumerating these commands here is to verify that all forbidden 1-byte commands
# can be distinguished from all permitted commands with fewer than EARLY_COMPARE_COMMAND_BITS bits
SPI_CMD_ERASE_FAST_BOOT    = 0x18;
SPI_CMD_WRITE_SECURITY_REG = 0x2F;
SPI_CMD_PER_30             = 0x30;
SPI_CMD_ENTER_QUAD_IO      = 0x35;
SPI_CMD_FACTORY_MODE_EN    = 0x41;
SPI_CMD_CHIP_ERASE_60      = 0x60;
SPI_CMD_RESET_ENABLE       = 0x66;
SPI_CMD_PES_75             = 0x75;
SPI_CMD_PER_7A             = 0x7A;
SPI_CMD_GANG_BLOCK_LOCK    = 0x7E;
SPI_CMD_WRITE_GLOBAL_FRZ   = 0xA6;
SPI_CMD_EXIT_DPD           = 0xAB;
SPI_CMD_PES_B0             = 0xB0;
SPI_CMD_ENTER_SECURE_OTP   = 0xB1;
SPI_CMD_SET_BURST_LEN      = 0xC0;
SPI_CMD_EXIT_SECURE_OTP    = 0xC1;
SPI_CMD_CHIP_ERASE_C7      = 0xC7;
SPI_CMD_ERASE_NV_LOCK_BITS = 0xE4;
SPI_CMD_EXIT_4B_ADDR_MODE  = 0xE9;
SPI_CMD_EXIT_QUAD_IO       = 0xF5;

white_list_cmds = [
    SPI_CMD_PAGE_PROGRAM,
    SPI_CMD_READ_SLOW,
    SPI_CMD_READ_SLOW_4BYTE,
    SPI_CMD_WRITE_DISABLE,
    SPI_CMD_READ_STATUS_REG,
    SPI_CMD_WRITE_ENABLE,
    SPI_CMD_READ_FAST,
    SPI_CMD_4B_READ_FAST,
    SPI_CMD_PAGE_PROGRAM_4BYTE,
    SPI_CMD_ERASE_4K,
    SPI_CMD_DUAL_OUT_FAST_RD,
    SPI_CMD_DUAL_OUT_FAST_RD_4BYTE,
    SPI_CMD_READ_SFDP,
    SPI_CMD_QUAD_OUT_FAST_RD,
    SPI_CMD_4B_QUAD_OUT_FAST_RD,
    SPI_READ_FLAG_STATUS_REGISTER,
    SPI_CMD_READ_ID,
    SPI_CMD_ENTER_4B_ADDR_MODE,
    SPI_CMD_DUAL_INOUT_FAST_RD,
    SPI_CMD_CLEAR_FLR,
    SPI_CMD_SECTOR_ERASE,
    SPI_CMD_4B_SECTOR_ERASE,
    SPI_CMD_ENTER_DPD
]

# Black list commands must be one-byte spi commands
black_list_cmds = [
    SPI_CMD_ERASE_FAST_BOOT,
    SPI_CMD_WRITE_SECURITY_REG,
    SPI_CMD_FACTORY_MODE_EN,
    SPI_CMD_CHIP_ERASE_60,
    SPI_CMD_RESET_ENABLE,
    SPI_CMD_PES_75,
    SPI_CMD_PER_7A,
    SPI_CMD_GANG_BLOCK_LOCK,
    SPI_CMD_WRITE_GLOBAL_FRZ,
    SPI_CMD_EXIT_DPD,
    SPI_CMD_PES_B0,
    SPI_CMD_ENTER_SECURE_OTP,
    SPI_CMD_SET_BURST_LEN,
    SPI_CMD_EXIT_SECURE_OTP,
    SPI_CMD_CHIP_ERASE_C7,
    SPI_CMD_ERASE_NV_LOCK_BITS,
    SPI_CMD_EXIT_QUAD_IO
]

# Override default white_list_cmds
white_list_cmds = [
        0x03, 0x13, 0x0b, 0x0c, 0x6b, 0x6c, 0x01, 0x05, 0x35, 0x06, 0x04, 0x20, 0x21, 0x9f, 0x5a, 0xb7, 0xe9, 0x32, 0x34, 0xd8, 0xdc, 0x02, 0x12, 0x15, 0x31, 0x3b, 0x3c
]

# Override default one-byte black_list_cmds
#black_list_cmds = [
#        0x18, 0x2f, 0xc1, 0x33
#]

# number of bits required to distinguish all permitted commands from all forbidden one byte commands
EARLY_COMPARE_COMMAND_BITS = 6;

def bits(num, bit_end, bit_start):
    mask = (1 << (bit_end - bit_start + 1)) - 1
    return ((num >> bit_start) & mask)

for b_cmd in black_list_cmds:
    for w_cmd in white_list_cmds:
        if bits(b_cmd, 7, 8 - EARLY_COMPARE_COMMAND_BITS) == \
                bits(w_cmd, 7, 8 - EARLY_COMPARE_COMMAND_BITS):
            print("Illegal parameterization: EARLY_COMPARE_COMMAND_BITS not large enough to distinguish all permitted SPI commands from all forbidden one-byte SPI commands")
            print("White list command:", hex(w_cmd))
            print("Black list command:", hex(b_cmd))

