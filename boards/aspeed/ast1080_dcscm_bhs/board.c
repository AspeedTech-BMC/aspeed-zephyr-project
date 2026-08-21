/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include "gpio/gpio_aspeed.h"

LOG_MODULE_REGISTER(board);

/*
 * The PFR application calls aspeed_print_sysrst_info() (defined for AST10x0/g1
 * in zephyr/soc/aspeed/ast10x0/soc.c). The AST10x0-G2 SoC does not provide it,
 * so supply it here to avoid modifying the BSP.
 * TODO(AST1080): implement real G2 reset-cause decoding once the SCU reset-log
 * register map for the CM4 is confirmed.
 */
void aspeed_print_sysrst_info(void)
{
	printk("RST: (AST1080/G2 reset-cause reporting not yet implemented)\n");
}

/*
 * AST1080 (AST10x0-G2) exposes a single GPIO controller "gpio0" split into
 * 32-pin bank sub-nodes (gpio0_0_31, gpio0_32_63, gpio0_64_95, ...), unlike
 * the AST1060 which used letter-banked nodes (gpio0_i_l, gpio0_e_h).
 *
 * Pin mapping below cross-referenced against the equivalent signals on
 * AST2700 DCSCM - see ast1080_dcscm_gpio_common.dts /
 * ast1080_dcscm_gpio_bhs.dts for the rest of the pin map.
 *   - AST1060 GPIOL2 -> AST1080 GPIO190, bank gpio0_160_191, offset 30
 *   - AST1060 GPIOL3 -> AST1080 GPIO192, bank gpio0_192_193, offset 0
 *   - AST1060 GPIOH3 -> AST1080 GPIO45,  bank gpio0_32_63,   offset 13
 */
static int ast1080_dcscm_bhs_post_init(void)
{
	// Enable flash power by SMB_SCM_EN (GPIO190) and SMB_BMC_PFR_SCM_SW (GPIO192)
	const struct device *dev;
	dev = device_get_binding("gpio0_160_191");
	gpio_pin_configure(dev, 30, GPIO_OUTPUT_ACTIVE);
	dev = device_get_binding("gpio0_192_193");
	gpio_pin_configure(dev, 0, GPIO_OUTPUT_ACTIVE);
	k_busy_wait(10000);
	return 0;
}

static int ast1080_dcscm_bhs_init(void)
{
#if defined(CONFIG_INTEL_PFR_CPLD_UPDATE)
	const struct device *dev;
	dev = device_get_binding("gpio0_32_63");
	gpio_pin_configure(dev, 13, GPIO_OUTPUT_ACTIVE);
#endif

	RTCRSTControl(false);
	return 0;
}

SYS_INIT(ast1080_dcscm_bhs_init, APPLICATION, 0);
SYS_INIT(ast1080_dcscm_bhs_post_init, POST_KERNEL, 60);
