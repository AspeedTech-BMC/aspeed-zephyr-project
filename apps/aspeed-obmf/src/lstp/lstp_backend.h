/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LSTP_BACKEND_H
#define LSTP_BACKEND_H

#include <stdint.h>

#include <zephyr/devicetree.h>
#include <zephyr/sys/util.h>

#include "lstp_common.h"

#define LSTP_BACKEND_NODE DT_COMPAT_GET_ANY_STATUS_OKAY(aspeed_obmf_lstp)

#if !DT_NODE_EXISTS(LSTP_BACKEND_NODE)
#error "aspeed-obmf requires an enabled aspeed,obmf-lstp topology node"
#endif

#define LSTP_I2C_NODE DT_PHANDLE(LSTP_BACKEND_NODE, i2c_controller)
#define LSTP_UART_NODE DT_PHANDLE(LSTP_BACKEND_NODE, uart_controller)

#define LSTP_SPI_DEVICE_COUNT DT_PROP_LEN_OR(LSTP_BACKEND_NODE, spi_devices, 0)
#define LSTP_GPIO_BANK_COUNT  DT_PROP_LEN_OR(LSTP_BACKEND_NODE, gpio_controllers, 0)
#define LSTP_DIRECT_GPIO_NUM  (LSTP_GPIO_BANK_COUNT * 32U)
#define LSTP_VWIRE_GPIO_BASE  DT_PROP(LSTP_BACKEND_NODE, vwire_gpio_base)
/* Virtual wires are GPIO-channel lines fed by the eSPI bridge; need both. */
#define LSTP_VWIRE_GPIO_COUNT \
	((IS_ENABLED(CONFIG_OBMF_ESPI_BRIDGE) && IS_ENABLED(CONFIG_OBMF_LSTP_GPIO_CHANNEL)) ? \
	 DT_PROP(LSTP_BACKEND_NODE, vwire_gpio_count) : 0U)
#define LSTP_GPIO_NUM         (LSTP_DIRECT_GPIO_NUM + LSTP_VWIRE_GPIO_COUNT)

#define LSTP_SPI_CHANNEL_NAME  DT_PROP(LSTP_BACKEND_NODE, spi_channel_name)
#define LSTP_I2C_CHANNEL_NAME  DT_PROP(LSTP_BACKEND_NODE, i2c_channel_name)
#define LSTP_UART_CHANNEL_NAME DT_PROP(LSTP_BACKEND_NODE, uart_channel_name)

#define LSTP_HAS_SPI_CHANNEL  IS_ENABLED(CONFIG_OBMF_LSTP_SPI_CHANNEL)
#define LSTP_HAS_I2C_CHANNEL  IS_ENABLED(CONFIG_OBMF_LSTP_I2C_CHANNEL)
#define LSTP_HAS_GPIO_CHANNEL IS_ENABLED(CONFIG_OBMF_LSTP_GPIO_CHANNEL)
#define LSTP_HAS_UART_CHANNEL 1
#define LSTP_HAS_MMIO_CHANNEL \
	(DT_PROP(LSTP_BACKEND_NODE, mmio_channel) && IS_ENABLED(CONFIG_OBMF_ESPI_MMIO))

/* Keep channel IDs dense: the BMC enumerates 1..num_channels. */
#define LSTP_MGMT_CHANNEL_ID 0U
#define LSTP_SLOT_SPI        (LSTP_MGMT_CHANNEL_ID + 1U)
#define LSTP_SLOT_I2C        (LSTP_SLOT_SPI + LSTP_HAS_SPI_CHANNEL)
#define LSTP_SLOT_GPIO       (LSTP_SLOT_I2C + LSTP_HAS_I2C_CHANNEL)
#define LSTP_SLOT_UART       (LSTP_SLOT_GPIO + LSTP_HAS_GPIO_CHANNEL)
#define LSTP_SLOT_MMIO       (LSTP_SLOT_UART + LSTP_HAS_UART_CHANNEL)

#define LSTP_NUM_CHANNELS    (LSTP_SLOT_MMIO + LSTP_HAS_MMIO_CHANNEL)

/* Never a valid channel ID; the ID of every channel the topology leaves out. */
#define LSTP_CHANNEL_ID_NONE 0xFFU

#define LSTP_SPI_CHANNEL_ID  (LSTP_HAS_SPI_CHANNEL ? LSTP_SLOT_SPI : LSTP_CHANNEL_ID_NONE)
#define LSTP_I2C_CHANNEL_ID  (LSTP_HAS_I2C_CHANNEL ? LSTP_SLOT_I2C : LSTP_CHANNEL_ID_NONE)
#define LSTP_GPIO_CHANNEL_ID (LSTP_HAS_GPIO_CHANNEL ? LSTP_SLOT_GPIO : LSTP_CHANNEL_ID_NONE)
#define LSTP_UART_CHANNEL_ID (LSTP_HAS_UART_CHANNEL ? LSTP_SLOT_UART : LSTP_CHANNEL_ID_NONE)
#define LSTP_MMIO_CHANNEL_ID (LSTP_HAS_MMIO_CHANNEL ? LSTP_SLOT_MMIO : LSTP_CHANNEL_ID_NONE)

/* An exported channel needs the topology fields that describe it. */
#if LSTP_HAS_SPI_CHANNEL && !DT_NODE_HAS_PROP(LSTP_BACKEND_NODE, spi_devices)
#error "CONFIG_OBMF_LSTP_SPI_CHANNEL requires spi-devices in the topology"
#endif
#if LSTP_HAS_I2C_CHANNEL && !DT_NODE_HAS_PROP(LSTP_BACKEND_NODE, i2c_controller)
#error "CONFIG_OBMF_LSTP_I2C_CHANNEL requires i2c-controller in the topology"
#endif
#if LSTP_HAS_GPIO_CHANNEL && !DT_NODE_HAS_PROP(LSTP_BACKEND_NODE, gpio_controllers)
#error "CONFIG_OBMF_LSTP_GPIO_CHANNEL requires gpio-controllers in the topology"
#endif
#if !IS_ENABLED(CONFIG_OBMF_LSTP_UART_SHELL) && \
	!DT_NODE_HAS_PROP(LSTP_BACKEND_NODE, uart_controller)
#error "The UART channel requires uart-controller unless CONFIG_OBMF_LSTP_UART_SHELL"
#endif
#if IS_ENABLED(CONFIG_OBMF_ESPI_BRIDGE) && \
	!(DT_NODE_HAS_PROP(LSTP_BACKEND_NODE, espi_controller) && \
	  DT_NODE_HAS_PROP(LSTP_BACKEND_NODE, snoop_controller))
#error "CONFIG_OBMF_ESPI_BRIDGE requires espi-controller and snoop-controller"
#endif

#if LSTP_VWIRE_GPIO_COUNT > 0
#if LSTP_VWIRE_GPIO_BASE != LSTP_DIRECT_GPIO_NUM
#error "eSPI virtual wires must be appended after the direct GPIO banks"
#endif
#endif

BUILD_ASSERT(LSTP_SPI_DEVICE_COUNT <= 1U,
	     "LSTP SPI channel exports one device: spi-devices takes at most one phandle");
BUILD_ASSERT(!LSTP_HAS_SPI_CHANNEL || LSTP_SPI_DEVICE_COUNT == 1U,
	     "CONFIG_OBMF_LSTP_SPI_CHANNEL requires one device in spi-devices");
BUILD_ASSERT(!LSTP_HAS_GPIO_CHANNEL || LSTP_GPIO_BANK_COUNT > 0U,
	     "LSTP topology must provide at least one direct GPIO bank");
BUILD_ASSERT(LSTP_NUM_CHANNELS <= LSTP_CHANNEL_ID_NONE,
	     "LSTP channel IDs must stay distinct from LSTP_CHANNEL_ID_NONE");
BUILD_ASSERT(LSTP_GPIO_NUM <= UINT8_MAX,
	     "LSTP GPIO descriptor uses an 8-bit GPIO count");
BUILD_ASSERT(LSTP_VWIRE_GPIO_COUNT <= 16U,
	     "AST1040 VWire GPIO backend supports at most 16 logical pins");

#endif /* LSTP_BACKEND_H */
