/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LSTP_GPIO_H
#define LSTP_GPIO_H

#include <stdint.h>

/*
 * Virtual-wire pins appended after the direct GPIO banks. Whoever owns the
 * eSPI virtual wires registers these; pin is relative to vwire-gpio-base.
 */
struct lstp_gpio_vwire_ops {
	int (*get_pin)(uint16_t pin);
	int (*set_pin)(uint16_t pin, uint8_t value);
};

/*
 * Callers (the obmf shell, the eSPI bridge) are built whether or not the GPIO
 * channel is; without it these are no-ops, so they never depend on the
 * optimizer dropping a reference to a function that was not compiled.
 */
#ifdef CONFIG_OBMF_LSTP_GPIO_CHANNEL
void lstp_gpio_set_vwire_ops(const struct lstp_gpio_vwire_ops *ops);

/* ISR-safe: report a virtual-wire pin change to the host. */
void lstp_gpio_vwire_event(uint16_t pin, uint8_t value);

uint32_t lstp_gpio_get_irq_drops(void);
uint32_t lstp_gpio_get_event_drops(void);
#else
static inline void lstp_gpio_set_vwire_ops(const struct lstp_gpio_vwire_ops *ops)
{
	(void)ops;
}
static inline void lstp_gpio_vwire_event(uint16_t pin, uint8_t value)
{
	(void)pin;
	(void)value;
}
static inline uint32_t lstp_gpio_get_irq_drops(void)
{
	return 0U;
}
static inline uint32_t lstp_gpio_get_event_drops(void)
{
	return 0U;
}
#endif

#endif /* LSTP_GPIO_H */
