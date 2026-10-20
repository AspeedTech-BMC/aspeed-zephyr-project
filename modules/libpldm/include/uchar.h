/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 * libpldm includes <uchar.h> for char16_t and char32_t only. The picolibc in
 * Zephyr SDK 0.16 doesn't ship it; defer to the C library's where it exists.
 */

#pragma once

#if __has_include_next(<uchar.h>)
#include_next <uchar.h>
#else
#include <stdint.h>

typedef uint_least16_t char16_t;
typedef uint_least32_t char32_t;
#endif
