/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include "flash/flash_master.h"
#include <flash/flash_aspeed.h>
#include <flash/flash_wrapper.h>

/**
 * Get a set of capabilities supported by the SPI master.
 *
 * @param spi The SPI master to query.
 *
 * @return A capabilities bitmask for the SPI master.
 */
uint32_t flash_master_capabilities(struct flash_master *spi)
{
	return FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
	       FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;
}

int flash_master_wrapper_init(struct flash_master_wrapper *spi)
{

	spi->base.capabilities = (int (*)(struct flash_master *spi))flash_master_capabilities;
	// spi->base.xfer = (int (*)(struct flash_master *spi, const struct flash_xfer *)) SPI_Command_Xfer;
	spi->base.xfer = (int (*)(struct spi_flash *flash, const struct flash_xfer *))SPI_Command_Xfer;

	return 0;
}
