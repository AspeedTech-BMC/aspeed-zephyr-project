/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "spi_filter/spi_filter_interface.h"
#include "spi_filter/spi_filter_aspeed.h"

#define SPI_FILTER_READ_PRIV 0
#define SPI_FILTER_WRITE_PRIV 1

#define SPI_FILTER_PRIV_ENABLE 0
#define SPI_FILTER_PRIV_DISABLE 1

struct spi_filter_engine_wrapper{
    struct spi_filter_interface base;
    int dev_id;
};

int spi_filter_wrapper_init (struct spi_filter_engine_wrapper *spi_filter);
