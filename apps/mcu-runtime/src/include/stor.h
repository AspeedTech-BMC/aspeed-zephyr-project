/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _STOR_H
#define _STOR_H

#include "ast_loader.h"

int stor_board_init(struct ast_loader *loader);
enum boot_mode_type boot_mode(void);
#endif
