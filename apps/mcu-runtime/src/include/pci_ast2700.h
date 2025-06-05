/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Aspeed Technology Inc.
 */
#ifndef _PCI_AST2700_H
#define _PCI_AST2700_H

#define ASPEED_PLDA1_BASE		0x12c15000
#define ASPEED_PLDA1_PRESET0		(ASPEED_PLDA1_BASE + 0xb0)
#define ASPEED_PLDA1_PRESET1		(ASPEED_PLDA1_BASE + 0xb4)

#define ASPEED_PLDA2_BASE		0x12c15800
#define ASPEED_PLDA2_PRESET0		(ASPEED_PLDA2_BASE + 0xb0)
#define ASPEED_PLDA2_PRESET1		(ASPEED_PLDA2_BASE + 0xb4)

int pci_init(void);

#endif
