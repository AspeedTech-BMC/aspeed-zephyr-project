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
#include "Smbus_mailbox/Smbus_mailbox.h"

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
void platform_monitor_init(void)
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

void platform_monitor_remove(void)
{
	struct gpio_dt_spec bmc_rstind =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), bmc_rst_ind_in_gpios, 0);
	gpio_pin_interrupt_configure_dt(&bmc_rstind, GPIO_INT_DISABLE);
	gpio_remove_callback(bmc_rstind.port, &bmc_rstind_cb_data);
}

#if defined(CONFIG_INIT_POWER_SEQUENCE)
static struct gpio_callback rst_bmc_srst_cb_data;
static struct gpio_callback rst_rsmrst_cb_data;
void power_sequence_handler(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	uint8_t gpio_pin = 31 - __builtin_clz(pins);
	static int count = 2;

	gpio_pin_interrupt_configure(dev, gpio_pin, GPIO_INT_DISABLE);
	gpio_remove_callback(dev, cb);

	int ret = gpio_pin_get(dev, gpio_pin);
	LOG_INF("[CPLD->PFR] Interrupt [%s %d]=%d", dev->name, gpio_pin, ret);

	if (--count == 0) {
		LOG_INF("Power sequence passes");
		GenerateStateMachineEvent(INIT_DONE, NULL);
		SetPlatformState(CPLD_NIOS_II_PROCESSOR_STARTED);
	}
}

void power_sequence(void)
{
	struct gpio_dt_spec rst_bmc_srst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), rst_srst_bmc_in_gpios, 0);
	struct gpio_dt_spec rst_rsmrst =
		GPIO_DT_SPEC_GET_BY_IDX(DT_INST(0, demo_gpio_basic_api), rst_rsmrst_in_gpios, 0);

	gpio_pin_configure_dt(&rst_bmc_srst, GPIO_INPUT);
	gpio_init_callback(&rst_bmc_srst_cb_data, power_sequence_handler, BIT(rst_bmc_srst.pin));
	gpio_add_callback(rst_bmc_srst.port, &rst_bmc_srst_cb_data);
	/* RESET INACTIVE means CPLD releases the RESET PIN */
	gpio_pin_interrupt_configure_dt(&rst_bmc_srst, GPIO_INT_LEVEL_INACTIVE);

	gpio_pin_configure_dt(&rst_rsmrst, GPIO_INPUT);
	gpio_init_callback(&rst_rsmrst_cb_data, power_sequence_handler, BIT(rst_rsmrst.pin));
	gpio_add_callback(rst_rsmrst.port, &rst_rsmrst_cb_data);
	/* RESET INACTIVE means CPLD releases the RESET PIN */
	gpio_pin_interrupt_configure_dt(&rst_rsmrst, GPIO_INT_LEVEL_INACTIVE);
}
#endif
