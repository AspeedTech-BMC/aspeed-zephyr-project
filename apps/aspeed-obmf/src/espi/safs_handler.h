/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SAFS_HANDLER_H
#define SAFS_HANDLER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define SAFS_FLASH_SIZE (8 * 1024 * 1024) /* 8MB Flash Window */

int safs_init(void);
int safs_flash_read(uint32_t offset, void *buf, size_t len);
int safs_flash_write(uint32_t offset, const void *buf, size_t len);
int safs_flash_erase(uint32_t offset, size_t len);
size_t safs_flash_get_size(void);

#endif /* SAFS_HANDLER_H */
