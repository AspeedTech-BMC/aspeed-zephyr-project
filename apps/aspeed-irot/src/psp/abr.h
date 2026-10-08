/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <zephyr/device.h>
#include <zephyr/sys/util_macro.h>

/* SSP view of the AST2700 IO die registers (0x14xxxxxx -> 0x74xxxxxx) */
#define SCU1_REG		0x74c02000
#define WDTA_REG		0x74c37400

#define ABR_REG			(SCU1_REG + 0x030)
#define ABR_EN			BIT(0)
#define ABR_MODE		BIT(29)

bool abr_enabled(void);
uint32_t abr_get_ind(void);

/*
 * Get the offset of the active image region within the boot flash. The
 * offset is non-zero only when the alternate boot indicator is set in
 * single-flash ABR mode, where the backup image lives in the upper half of
 * the flash. Returns -EINVAL if that half cannot be located because the
 * flash size strap is unset.
 */
int abr_get_flash_offset(uint32_t *offset);

/*
 * flash_read() wrapper for accesses to the boot image region. The offset is
 * relative to the start of the active image region and is shifted by
 * abr_get_flash_offset(), so callers do not need to know whether ABR is
 * active.
 */
int abr_flash_read(const struct device *dev, off_t offset, void *data, size_t len);
