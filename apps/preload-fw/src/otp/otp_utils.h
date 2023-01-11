/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#define OTP_IMAGE_ADDR 0x800e0000

enum otp_status {
	OTP_SUCCESS             = 0,
	OTP_USAGE               = -1,
	OTP_FAILURE             = -2,
	OTP_INVALID_HEADER      = -3,
	OTP_INVALID_SOC         = -4,
	OTP_INVALID_CHECKSUM    = -5,
	OTP_PROTECTED           = -6,
	OTP_PROG_FAILED         = -7,
};

bool is_otp_secureboot_en(enum otp_status *otp_rc);
int otp_prog(uint32_t addr);
