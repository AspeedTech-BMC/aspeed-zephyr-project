/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _PCI_AST2700_H
#define _PCI_AST2700_H

#include <chip.h>

#define ASPEED_PLDA1_BASE		0x12c15000
#define ASPEED_PLDA2_BASE		0x12c15800
#define   PLDA_MSI_CAP			(0x10)
#define   PLDA_PRESET0			(0xb0)
#define   PLDA_PRESET1			(0xb4)

#define ASPEED_PLDA3_BASE		0x14c1c000
#define ASPEED_PLDA3_MSI_CAP		(ASPEED_PLDA3_BASE + 0x10)

int pci_init(struct ast_chip *chip);

#endif
