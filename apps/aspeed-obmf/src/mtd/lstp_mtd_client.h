/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef LSTP_MTD_CLIENT_H
#define LSTP_MTD_CLIENT_H

#include <stddef.h>
#include <stdint.h>

int lstp_mtd_read_jedec_id(uint8_t id[3]);
int lstp_mtd_read(uint32_t offset, void *buf, size_t len);
int lstp_mtd_write(uint32_t offset, const void *buf, size_t len);
int lstp_mtd_erase(uint32_t offset, size_t len);

#endif /* LSTP_MTD_CLIENT_H */
