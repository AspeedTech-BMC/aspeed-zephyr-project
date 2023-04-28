/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

unsigned char ca1_cert_der[] = {
  0x30, 0x82, 0x01, 0xd0, 0x30, 0x82, 0x01, 0x56, 0xa0, 0x03, 0x02, 0x01,
  0x02, 0x02, 0x14, 0x3f, 0xc6, 0x46, 0x4d, 0x50, 0xf7, 0xd7, 0x9e, 0x77,
  0x9c, 0x37, 0x05, 0xcf, 0xed, 0x6f, 0x90, 0x33, 0x7d, 0x30, 0x82, 0x30,
  0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30,
  0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14,
  0x69, 0x6e, 0x74, 0x65, 0x6c, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x45,
  0x43, 0x50, 0x33, 0x38, 0x34, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,
  0x32, 0x32, 0x30, 0x35, 0x32, 0x30, 0x30, 0x38, 0x33, 0x39, 0x30, 0x35,
  0x5a, 0x17, 0x0d, 0x33, 0x32, 0x30, 0x35, 0x31, 0x37, 0x30, 0x38, 0x33,
  0x39, 0x30, 0x35, 0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03,
  0x55, 0x04, 0x03, 0x0c, 0x14, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x20, 0x74,
  0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x50, 0x33, 0x38, 0x34, 0x20, 0x43,
  0x41, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
  0x04, 0x17, 0x2c, 0xe2, 0x49, 0xf4, 0xb8, 0xd2, 0xe1, 0x92, 0x32, 0xe3,
  0xf2, 0xf1, 0x3f, 0x57, 0x6b, 0x9a, 0x95, 0x41, 0xc2, 0xb8, 0x4a, 0xa9,
  0x1d, 0x41, 0x22, 0x00, 0x58, 0x92, 0x21, 0x3b, 0x21, 0x1a, 0x45, 0xc6,
  0x3c, 0xb4, 0x2a, 0x3a, 0x60, 0xf1, 0x85, 0x5a, 0x66, 0x8a, 0x5c, 0xe9,
  0xb4, 0xde, 0xd7, 0x81, 0x9a, 0xf6, 0x60, 0x32, 0x1a, 0xf7, 0x34, 0x39,
  0x74, 0x4a, 0xe9, 0x83, 0x4e, 0x1a, 0xa0, 0xe4, 0xcb, 0x26, 0xc9, 0x40,
  0x0c, 0x8b, 0x64, 0x01, 0x0c, 0xca, 0x0f, 0x3f, 0x56, 0x4e, 0xf9, 0xd7,
  0x7e, 0x8c, 0x5a, 0x7d, 0x51, 0x02, 0xbc, 0x51, 0x0f, 0x70, 0xd7, 0xeb,
  0xea, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
  0x04, 0x16, 0x04, 0x14, 0x35, 0x27, 0x17, 0x1a, 0x24, 0xf2, 0xd5, 0x44,
  0xdd, 0x62, 0xe0, 0xf6, 0x5a, 0x0e, 0x11, 0x10, 0x20, 0x04, 0x79, 0x3f,
  0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
  0x14, 0x35, 0x27, 0x17, 0x1a, 0x24, 0xf2, 0xd5, 0x44, 0xdd, 0x62, 0xe0,
  0xf6, 0x5a, 0x0e, 0x11, 0x10, 0x20, 0x04, 0x79, 0x3f, 0x30, 0x0f, 0x06,
  0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01,
  0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
  0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0x8b, 0xde,
  0x42, 0xb1, 0x13, 0x2d, 0xa8, 0x0f, 0x63, 0x9c, 0xd9, 0xe9, 0xd0, 0x1a,
  0x94, 0x4e, 0x55, 0xe2, 0xc1, 0x6f, 0x25, 0xc8, 0xe0, 0xc5, 0x95, 0x93,
  0xeb, 0x70, 0x56, 0xde, 0xab, 0x81, 0x53, 0xfb, 0x88, 0x79, 0x56, 0xcc,
  0x49, 0x09, 0x7a, 0x4f, 0x70, 0x5e, 0x8c, 0x43, 0x80, 0xef, 0x02, 0x30,
  0x23, 0xc9, 0x26, 0x7b, 0xda, 0x32, 0x1f, 0x29, 0xad, 0xfc, 0x20, 0x98,
  0x95, 0xad, 0x74, 0x6d, 0x50, 0x90, 0xb5, 0x5f, 0x09, 0x9b, 0x8f, 0xf7,
  0xbf, 0xac, 0x5c, 0x3f, 0xa2, 0x54, 0x33, 0xb0, 0xe6, 0xb0, 0x09, 0xdb,
  0x9f, 0xcb, 0x7b, 0xcc, 0xb5, 0xe0, 0xf4, 0xf0, 0x35, 0x2b, 0xbe, 0x04
};
unsigned int ca1_cert_der_len = 468;