/*
 * Copyright (c) 2021 - 2023 ASPEED Technology Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ASPEED_SPI_ASPEED_NOR_H_
#define ASPEED_SPI_ASPEED_NOR_H_

#include <aspeed/spi_nor.h>
#include <zephyr/drivers/spi.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*spi_nor_transceive)(const struct device *dev,
				  const struct spi_config *config,
				  struct spi_nor_op_info op_info);
typedef int (*spi_nor_read_init)(const struct device *dev,
				 const struct spi_config *config,
				 struct spi_nor_op_info read_op_info);
typedef int (*spi_nor_write_init)(const struct device *dev,
				  const struct spi_config *config,
				  struct spi_nor_op_info write_op_info);

struct spi_nor_ops {
	spi_nor_transceive transceive;
	spi_nor_read_init read_init;
	spi_nor_write_init write_init;
};

/** Return the ASPEED NOR operations, or NULL for another SPI driver. */
const struct spi_nor_ops *spi_aspeed_nor_get_ops(const struct device *dev);

#ifdef __cplusplus
}
#endif

#endif /* ASPEED_SPI_ASPEED_NOR_H_ */
