/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ESPI_MMBI_H
#define ESPI_MMBI_H

/*
 * MMBI window layout. The bridge keeps host MEMWR off these regions and
 * names them in traces. The descriptor must start at the host LGMR base;
 * keep the OBMF mirrors above it.
 */
#define MMBI_INSTANCE_OFFSET    0x0000U
#define MMBI_INSTANCE_SIZE      0x8000U /* 32 KiB */
#define MMBI_HALF_SIZE          (MMBI_INSTANCE_SIZE / 2U)

#define MMBI_DESCRIPTOR_OFFSET  MMBI_INSTANCE_OFFSET
#define MMBI_DESCRIPTOR_SIZE    64U

#define MMBI_HROP_OFFSET        (MMBI_DESCRIPTOR_OFFSET + MMBI_DESCRIPTOR_SIZE)
#define MMBI_HROP_SIZE          8U

#define MMBI_B2H_CB_OFFSET      (MMBI_HROP_OFFSET + MMBI_HROP_SIZE)
#define MMBI_B2H_CB_SIZE        (MMBI_HALF_SIZE - MMBI_DESCRIPTOR_SIZE - MMBI_HROP_SIZE)

#define MMBI_HRWP_OFFSET        (MMBI_INSTANCE_OFFSET + MMBI_HALF_SIZE)
#define MMBI_HRWP_SIZE          8U

#define MMBI_H2B_CB_OFFSET      (MMBI_HRWP_OFFSET + MMBI_HRWP_SIZE)
#define MMBI_H2B_CB_SIZE        (MMBI_HALF_SIZE - MMBI_HRWP_SIZE)

#endif /* ESPI_MMBI_H */
