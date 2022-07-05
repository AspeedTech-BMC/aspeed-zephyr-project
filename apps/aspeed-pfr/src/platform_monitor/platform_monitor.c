/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <zephyr.h>
#include <drivers/gpio.h>
#include <logging/log.h>
#include "StateMachineAction/StateMachineActions.h"
#include "AspeedStateMachine/AspeedStateMachine.h"

LOG_MODULE_REGISTER(monitor, CONFIG_LOG_DEFAULT_LEVEL);

AO_DATA BmcAOData;
static EVENT_CONTEXT BmcData[2];
static struct gpio_callback bmc_rstind_cb_data;
void bmc_rstind_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	int ret = gpio_pin_get(dev, gpio_pin);
	LOG_INF("[BMC->PFR] RSTIND[%s %d] = %d", dev->name, gpio_pin, ret);

	GenerateStateMachineEvent(RESET_DETECTED, NULL);
}

/* Monitor BMC Reset Status */
void platform_monitor_init()
{
	int ret;
	struct gpio_dt_spec bmc_rstind =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), bmc_rst_ind_in_gpios, 0);
	ret = gpio_pin_configure_dt(&bmc_rstind, GPIO_INPUT);
	LOG_INF("BMC: gpio_pin_configure_dt[%s %d] = %d", bmc_rstind.port->name, bmc_rstind.pin, ret);
	ret = gpio_pin_interrupt_configure_dt(&bmc_rstind, GPIO_INT_EDGE_FALLING);
	LOG_INF("BMC: gpio_pin_interrupt_configure_dt = %d", ret);
	gpio_init_callback(&bmc_rstind_cb_data, bmc_rstind_handler, BIT(bmc_rstind.pin));
	ret = gpio_add_callback(bmc_rstind.port, &bmc_rstind_cb_data);
	LOG_INF("BMC: gpio_add_callback = %d", ret);
}

void platform_monitor_remove()
{
	struct gpio_dt_spec bmc_rstind =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), bmc_rst_ind_in_gpios, 0);
	gpio_pin_interrupt_configure_dt(&bmc_rstind, GPIO_INT_DISABLE);
	gpio_remove_callback(bmc_rstind.port, &bmc_rstind_cb_data);
}
