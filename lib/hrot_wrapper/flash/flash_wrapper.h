/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "flash/flash_master.h"
#include "flash/spi_flash.h"
#include "flash/flash_aspeed.h"

struct flash_master_wrapper {
	struct flash_master base;
};

struct spi_engine_wrapper {
	struct spi_flash spi;
};

struct xfer_engine_wrapper {
	struct flash_xfer base;
};

/**
 * Check the requested operation to ensure it is valid for the device.
 */
#define SPI_FLASH_BOUNDS_CHECK(bytes, addr, len)	 \
	if (addr >= bytes) {				 \
		return SPI_FLASH_ADDRESS_OUT_OF_RANGE;	 \
	}						 \
							 \
	if ((addr + len) > bytes) {			 \
		return SPI_FLASH_OPERATION_OUT_OF_RANGE; \
	}

int flash_wrapper_init(struct spi_engine_wrapper *spi, struct flash_master_wrapper *engine);
